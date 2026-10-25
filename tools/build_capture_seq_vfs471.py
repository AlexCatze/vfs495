#!/usr/bin/env python3
"""Build the VFS471 in-session command sequence (data/vfs471/capture_seq.json).

The sequence the driver replayed until now was the VFS495's. Its `0x02` sensor
programs are byte-identical on the 471, but its `0x06` firmware patches are
495 patches (405/2581/1301 B). The 471 rejects them by rebooting off the USB bus,
which is where every "imaging-latch re-enumeration" and the ~25 s warm-up came
from. HP's own 471 trace sends 471 patches (1845/2629/1813 B) and never
re-enumerates.

This script decrypts HP's 471 session from a usblog trace plus the master secret
dumped from HP's binary (gdb), then builds a 28-command sequence with the
driver's existing slot layout:

  0..13   HP 471, verbatim: 1a, 06 patch A, 02, 1a, 06 calib patch, 8 sweeps
          (the 471 repeats PgaOffset), 12  -- the old slot 0 (`1f05`, not sent
          by HP on the 471) is gone, the extra sweep takes its place
  14..20  1a, 06 patch A, poll, 1a, 06 init patch 1, 1a, 06 patch A
  21..27  the recorded poll/imaging/latch commands (no 471 imaging trace
          exists yet), with every calibration override set to HP's 471 values

Usage:
  build_capture_seq_vfs471.py --trace trace.usblog --secrets secrets.txt \
      --base <vfs495 capture_seq.json> --out data/vfs471/capture_seq.json
"""
import argparse
import hashlib
import json
import re
import sys

from Crypto.Cipher import AES


def ssl3_prf(secret, a, b, n):
    out, i = b"", 0
    while len(out) < n:
        salt = bytes([0x41 + i]) * (i + 1)
        out += hashlib.md5(secret + hashlib.sha1(salt + secret + a + b).digest()).digest()
        i += 1
    return out[:n]


def read_master(path):
    txt = open(path).read().split("DUMP_MASTER")[1]
    m = bytes(int(x, 16) for x in re.findall(r"\t0x([0-9a-f]{2})", txt))[:48]
    if len(m) != 48:
        sys.exit("no 48-byte DUMP_MASTER in " + path)
    return m


def read_trace(path):
    ev = []
    pat = re.compile(r"\S+ (OUT|IN) +ep=(\w+) (?:len|req)=\d+ ret=(-?\d+) data=(\w*)")
    for line in open(path):
        m = pat.match(line.strip())
        if m and m[2] == "01":
            ev.append((m[1], bytes.fromhex(m[4])))
    return ev


def records(buf):
    o = 0
    while o + 5 <= len(buf):
        ln = int.from_bytes(buf[o + 3:o + 5], "big")
        yield buf[o], buf[o + 5:o + 5 + ln]
        o += 5 + ln


def hp_session_commands(trace, secrets):
    """Plaintext of every AppData command HP sent, verified by MAC."""
    ev = read_trace(trace)
    cr = next(d[14:46] for k, d in ev if k == "OUT" and d[:1] == b"\x11" and d[8] == 1)
    sr = next(d[11:43] for k, d in ev if k == "IN" and d[:1] == b"\x16" and len(d) > 43 and d[5] == 2)
    master = read_master(secrets)
    kb = ssl3_prf(master, sr, cr, 136)
    cmac, ckey, civ = kb[0:20], kb[40:72], kb[104:120]
    seq, cmds, active = 0, [], False
    for kind, data in ev:
        if kind != "OUT":
            continue
        buf = data[3:] if data[:1] == b"\x11" else data
        for rtype, body in records(buf):
            if rtype == 0x14:
                active = True
                continue
            if not active:
                continue
            pt = AES.new(ckey, AES.MODE_CBC, civ).decrypt(body)
            civ = body[-16:]
            plain, mac = pt[: len(pt) - pt[-1] - 21], pt[len(pt) - pt[-1] - 21: len(pt) - pt[-1] - 1]
            inner = hashlib.sha1(cmac + b"\x36" * 40 + seq.to_bytes(8, "big") + bytes([rtype]) + plain).digest()
            if hashlib.sha1(cmac + b"\x5c" * 40 + inner).digest() != mac:
                sys.exit(f"MAC mismatch at client record {seq}: wrong secrets for this trace?")
            seq += 1
            if rtype == 0x17:
                cmds.append(plain)
    return cmds


REG_TLV = re.compile(rb"\x03\x00\x09\x00(....)(....)", re.S)
ADC_ENTRY = bytes.fromhex("05000e001420ffff00ff000000000000")


def overrides(cmd):
    """{addr: (offset, value)} of the last write to every register written twice
    or more (base table + override), plus the Adc override offsets."""
    seen = {}
    for m in REG_TLV.finditer(cmd):
        seen.setdefault(m[1], []).append((m.start(2), m[2]))
    regs = {a: w[-1] for a, w in seen.items() if len(w) >= 2}
    adc = [m.end() for m in re.finditer(re.escape(ADC_ENTRY), cmd)]
    return regs, adc


def transplant(target, source):
    """Copy the calibration override values of `source` into `target`."""
    out = bytearray(target)
    sregs, sadc = overrides(source)
    tregs, tadc = overrides(target)
    for addr, (off, _) in tregs.items():
        if addr in sregs:
            out[off:off + 4] = sregs[addr][1]
    for off in tadc:
        out[off] = source[sadc[-1]]
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True, help="HP usblog trace of a 471 session (e.g. dump/cv2/usb.log)")
    ap.add_argument("--secrets", required=True, help="gdb dump with DUMP_MASTER for that same run")
    ap.add_argument("--base", required=True, help="the recorded (VFS495) 28-command sequence")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    hp = hp_session_commands(a.trace, a.secrets)
    base = [bytes.fromhex(h) for h in json.load(open(a.base))]
    shape = [(c[0], len(c)) for c in hp[:17]]
    want = [(0x1a, 1), (0x06, 1845), (0x02, 2331), (0x1a, 1), (0x06, 2629)] + [(0x02, n) for n in
            (2711, 2503, 2516, 2516, 2742, 2612, 2625, 2666)] + [(0x12, 57), (0x1a, 1), (0x06, 1845), (0x02, 2691)]
    if shape != want or hp[18][0] != 0x06:
        sys.exit(f"unexpected HP 471 command shape: {shape}")
    if len(base) != 28 or [c[0] for c in base[21:]] != [0x02, 0x02, 0x17, 0x04, 0x02, 0x02, 0x17]:
        sys.exit("--base is not the 28-command recorded sequence")

    patch_a, patch_1, poll = hp[1], hp[18], hp[16]
    seq = hp[:17] + [b"\x1a", patch_1, b"\x1a", patch_a]
    seq += [transplant(c, poll) if c[0] == 0x02 else c for c in base[21:]]
    assert len(seq) == 28

    # Self-check: transplanting into the recorded poll must reproduce HP's 471 poll
    # everywhere except the per-command random SecurityParams (AES key/IV) TLV.
    t = transplant(base[16], poll)
    key = t.find(bytes.fromhex("06006a00"))
    diff = [i for i in range(len(t)) if t[i] != poll[i] and not key <= i < key + 4 + 0x6a]
    if diff:
        sys.exit(f"transplant self-check failed at offsets {diff[:10]}")

    json.dump([c.hex() for c in seq], open(a.out, "w"), indent=1)
    for i, c in enumerate(seq):
        print(f"{i:2} 0x{c[0]:02x} {len(c):5}B")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
