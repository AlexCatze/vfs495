# vfs495

An open-source userspace driver for the **Validity "Falcon" family** of swipe
fingerprint sensors, as shipped in 2010s-era HP laptops:

| Model | USB ID | Example laptop | Status |
| --- | --- | --- | --- |
| VFS495 | `138a:003f` | HP EliteBook 820 G3 | original target |
| VFS471 | `138a:003c` | HP EliteBook 2760p | added; live-confirmed |

The whole secure session, image capture and decode run in open Rust. There is
**no proprietary HP code in the session or login path**. Decoded images are fed
to libfprint's `virtual_image` driver, which makes the sensor usable through
stock **fprintd / PAM / login manager / `sudo`** with no custom C kernel or
libfprint driver.

The per-sensor differences (device ID, whether the handshake needs a client
certificate, the command sequence, calibration, imaging gate, reconstruction)
live in one place — [`src/device.rs`](src/device.rs) — and the right profile is
chosen automatically from the USB ID (or `--device <model>`). Per-model runtime
data lives in `data/<model>/` (see [`data/README.md`](data/README.md)).

> Status: research driver. The open secure session, transport, AES-256-CBC image
> decryption, decode and reconstruction all run in open Rust and are
> **live-confirmed on hardware**; a feeder daemon bridges it to libfprint for
> GNOME/fprintd. Remaining work is integration polish (see [Limitations](#limitations)).
> Contributions welcome. **A distilled project status & reverse-engineering
> reference is in [`docs/STATUS.md`](docs/STATUS.md)**; the full dated log is
> [`NOTES.md`](NOTES.md).

---

## Why this sensor was hard

The VFS495 wraps every command in a **proprietary variant of SSLv3-RSA**. Earlier
open efforts could build the session crypto but still had to run HP's closed
binary to establish each session, because owned sensors reject the handshake with
fatal alert `0x2f`.

The root cause, found here: on an **owned** sensor the `ClientKeyExchange` wraps
the premaster secret in `AES-256-CBC(s_key)` before RSA, where `s_key` is a
32-byte shared secret established at *pairing* ("TakeOwnership"). On an
**unowned** sensor that wrap is skipped, so a plain `RSA(premaster)` handshake
works with no pairing at all. This driver targets the unowned case and completes
the handshake entirely in open code — the wall every prior VFS495 project hit.

See [`NOTES.md`](NOTES.md) for the full reverse-engineering log and evidence.

---

## How it works

```
 USB (rusb)                                    libfprint
 138a:003c/3f                                  virtual_image
    │                                              ▲
    ▼                                              │  <i32 w><i32 h><pixels>
 init replay ─► open SSLv3 handshake ─► capture ─► DLI decode ─► feed socket
 (src/usb)      (src/session, src/crypto) (src/capture) (src/image) (src/virtimage)
```

| Module            | Responsibility                                                        |
|-------------------|-----------------------------------------------------------------------|
| `src/crypto.rs`   | Validity SSLv3 KDF, RSA (LE modulus, PKCS#1 v1.5), length-less MAC, AES-256-CBC record layer |
| `src/usb.rs`      | libusb transport (EP1 OUT/IN, EP2 image)                              |
| `src/session.rs`  | init replay + open handshake → active record layer                    |
| `src/capture.rs`  | in-session capture command + EP2 stream read                          |
| `src/image.rs`    | `UnpackLineRT` port (mode 4/8/general), descramble, assembly, finger-contact gate → PGM |
| `src/swipe.rs`    | swipe reconstruction at true scale (finger speed from the secondary sensing line) |
| `src/virtimage.rs`| feed a decoded image to `$FP_VIRTUAL_IMAGE`                           |

The crypto is validated **byte-exact** against a live trace of HP's binary — run
`vfs495 selftest` (see below).

---

## Build

Requires a Rust toolchain and libusb 1.0.

```sh
# Fedora:        sudo dnf install libusb1-devel
# Debian/Ubuntu: sudo apt install libusb-1.0-0-dev
cargo build --release
```

## Runtime data you must supply

Everything device-specific — firmware patch blobs, the sensor's RSA key, the
command sequences, the descramble table, and (VFS471) the client certificate and
key — is derived from HP's proprietary driver and is **not** distributed with
this repo. You extract it yourself into `data/<model>/`:

- Drop an HP package into `vendor/hp/<model>/` (both gitignored).
- Run the tooling in [`tools/`](tools/) to produce `data/<model>/`.

See [`data/README.md`](data/README.md) for the file list and
[`tools/README.md`](tools/README.md) for the extraction steps. This is the same
accepted compromise every open Validity driver makes (the firmware patches are
HP's and cannot be redistributed).

## Usage

```sh
# 1. Offline crypto self-test — no hardware needed (needs captures/skey_dump.json locally)
vfs495 selftest

# 2. Non-root USB access (recommended)
sudo cp packaging/70-vfs495.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger

# 3. Prove the open secure session against the real sensor
vfs495 handshake

# 4. Capture a swipe and decode it to a PGM
vfs495 capture --out capture.bin
vfs495 decode --input capture.bin --out fingerprint.pgm    # unpack + descramble + reconstruct
#   add --feed to write the image exactly as it is fed to libfprint (1.5x enlarged)

# ...or reconstruct from already-descrambled scan lines (fully-open, verifiable offline):
vfs495 decode-lines --input lines.raw --out fingerprint.pgm

# 5. End-to-end: hand a live swipe to libfprint's virtual_image
FP_VIRTUAL_IMAGE=/run/user/$(id -u)/vfs495.sock
#   (start fprintd/libfprint with the virtual_image driver pointed at that socket)
vfs495 run --socket "$FP_VIRTUAL_IMAGE"

# 6. Run continuously as a feeder daemon (for enroll/verify through fprintd):
#    captures whenever libfprint opens the device, pushes swipes to the socket.
sudo -E FP_VIRTUAL_IMAGE="$FP_VIRTUAL_IMAGE" vfs495 daemon
#    --once     capture one frame and exit (testing)
#    --min-contact 300 finger-detection threshold (rows with finger contact)
```

### GNOME / fprintd integration (feeder daemon)

GDM's fingerprint login is entirely fprintd/PAM-mediated — GDM never talks to the
driver. Once decoded images reach libfprint via `virtual_image`, `fprintd-enroll`
/ `fprintd-verify`, the GNOME Settings fingerprint UI, and PAM-based `sudo`/GDM
all work through the stock stack. The enroll → match → reject round-trip through
libfprint is proven in [`scripts/vimage_proof.py`](scripts/vimage_proof.py).

The **`vfs495 daemon`** command bridges the two: when fprintd opens the device it
captures a swipe, decodes it, and pushes the image to the `virtual_image` socket.
Routing the system `fprintd` through it is **a system-config change you must opt
into**:

```sh
cargo build --release
sudo ./scripts/system_install.sh    # binary + data to /usr/local, vfs495.service, fprintd drop-in
sudo ./scripts/system_selinux.sh    # SELinux systems only: lets fprintd create the socket
fprintd-enroll                      # five stages; swipe each time the Caps Lock LED lights
fprintd-verify
sudo ./scripts/system_uninstall.sh  # removes all of the above
```

The daemon stays idle until fprintd is waiting for a finger. It then calibrates
for about 9 s (do not touch the sensor) and opens swipe windows back to back: the
**Caps Lock LED is lit** while the sensor records (about 3 s of every 4;
`VFS_CUE_LED` in the unit). Swipe once while it is lit; each swipe is fed as soon
as its window closes. Every file the scripts
touch is listed in [`docs/SYSTEM_CHANGES.md`](docs/SYSTEM_CHANGES.md).

**This is a swipe sensor: slide your finger slowly down across it (1–2 s). A
finger held still does not produce a fingerprint image.**

Finger presence is decided by **contact rows**: rows of the decoded capture whose
spread, after removing the sensor's fixed column pattern, shows real skin contact
(`--min-contact`, default 300). Measured live: a blank sensor gives 0 contact rows,
a swipe ~6000. Each cycle the daemon fires a full imaging capture, decodes it, and
feeds it only if it clears the threshold. `vfs495 ridge-probe` prints the count and
the accept/reject verdict for one capture without gating (it prompts you to swipe).

Every capture session runs the sensor's AFE calibration itself: the open driver
computes the sweep results (PgaOffset, Adc, PgaGain) from its own calibration
frames, using ports of HP's step algorithms, and writes them into the commands
that follow (`src/calib.rs`). It used to replay the values recorded with the
command stream, and that let the no-finger noise drift up into the finger range.

> An earlier WOE-style poll-divergence gate (poll `0x02`, watch the reply for a
> jump on contact) was **removed** after hardware testing showed that poll is
> finger-blind — its reply and the pre-latch image stream do not change on contact.
> A low-power gate that avoids imaging on empty cycles would need the EP3 interrupt
> endpoint or a dedicated WOE command; not yet investigated.

---

## Limitations

- **Image decode is ported and verified byte-exact against HP on live sensor
  data.** `src/image.rs` is a clean-room reimplementation of `UnpackLineRT` (all
  three modes) plus line assembly and reconstruction. On this hardware the main
  image frames are mode 8 (width 264): the open `dst[perm[i]] = src[i]` unpack
  reproduces HP's `UnpackLineRT` output **byte-exact on every real image line**
  (verified via `scripts/dump_unpack_pairs.gdb.py` — 95/95 lines, 0 mismatches),
  and the descrambled-lines path reconstructs a real fingerprint (`decode-lines`,
  ridge period ~14 px). The DLI config is confirmed on-device with
  `scripts/dump_dli_config.gdb.py` (→ `captures/dli_config.json`, auto-loaded).
  A firm, steady swipe is needed for a full-height image.
- **Swipe reconstruction follows HP's method; live enroll + verify passes.**
  `src/swipe.rs` measures finger speed from the sensor's second sensing line (8
  rows upstream of the imaging line) and resamples to square 50 µm pixels, so
  swipes of different speed and angle come out at the same scale. Live enroll +
  verify through libfprint passes; a swipe that shows a mostly different part of
  the finger than any enrolled swipe is still rejected (see `docs/STATUS.md` §0).
  `scripts/loo_match.py` runs
  the offline match test, `scripts/pair_scores.py` pairwise scores.
- **Unowned sensors only.** Owned sensors need the pairing (`TakeOwnership`) flow
  — fully mapped in `NOTES.md` but not implemented, since it is a persistent,
  cycle-limited sensor write.
- **Finger detection is a ridge spectral-peak gate** on each decoded capture
  (`--min-ridge`, default 1.4; live-measured finger ~2.1 vs noise ~1.2). The daemon
  images every cycle and decides from the picture — safe, since imaging does not
  stress the sensor. The end-to-end daemon → fprintd enroll/verify run with a live
  finger is not yet exercised; the gate itself is validated via `ridge-probe`.
- **RSA modulus is per-device** and read from `captures/modulus.json`. The sensor
  delivers it in an opaque signed key blob during init (not a plain SSL
  certificate), so generic auto-extraction isn't wired up; on a different unit,
  dump your modulus with `scripts/dump_modulus.gdb.py`.

---

## Credits & prior art

This work stands on a large body of Validity reverse engineering:

- **[saifulmd0/vfs495-linux](https://github.com/saifulmd0/vfs495-linux)** —
  documented the VFS495 SSLv3 protocol (`docs/SSL_PROTOCOL.md`), the column
  descramble, and the image reconstruction approach. The crypto here is an
  independent re-implementation of that spec, validated against a live trace.
- **The [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
  project** — the `virtual_image` driver and the whole fprintd/PAM stack that
  make this usable for real logins.
- **The broader Validity/Synaptics RE community**, whose work on sibling sensors
  (VFS0050/0090/7552, `python-validity`, `vfs-tools`) mapped the device family's
  behaviour.

Reverse engineering here was done for interoperability, on hardware owned by the
author, to enable an open Linux driver.

## License

[MIT](LICENSE) © 2026 Hammad Majid.

No proprietary HP code is included in this repository.
