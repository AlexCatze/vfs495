# Extracting a sensor's runtime data

The driver needs per-model data files (see [`../data/README.md`](../data/README.md))
that are all derived from HP/Validity's proprietary driver. They are never
committed; you extract them yourself from an HP package. This directory holds the
tooling.

## 1. Drop HP's files in `vendor/hp/<model>/`

`vendor/` is gitignored. For each model you want to support, create
`vendor/hp/<model>/` and place:

- `validity-sensor` — HP's userspace tool (from the SoftPaq / `.deb`), used with
  `gdb` to read the keys, modulus and tables out of memory.
- `HPUsbVFS<MODEL>.img` — the firmware image (shipped alongside the tool).
- `trace.usblog` — a USB capture of one full HP run (`init` → handshake →
  `getprintwait`), taken with the `LD_PRELOAD` logger in `harness/`. Supplies the
  `init_seq`, the firmware patch blobs and the in-session `capture_seq`.
- `secrets.txt` — a `gdb` dump of the session master secret for that same trace
  (`DUMP_MASTER ...`), so the trace can be decrypted (needed by
  `build_capture_seq_*`).

> Only ever run the read-only / volatile HP verbs (`getver`, `getprintwait`, …).
> Never `setowner` / `resetowner` — those are persistent, cycle-limited writes.
> See the safety notes in the project docs.

## 2. Produce `data/<model>/`

Most values come straight out of HP's binary with the `gdb` scripts in
[`../scripts/`](../scripts/); point their output at the model's data dir with
`VFS_OUT`. The command sequence is rebuilt from the decrypted trace.

| Output | How |
| --- | --- |
| `modulus.json` | `VFS_OUT=data/<model>/modulus.json gdb -x scripts/dump_modulus.gdb.py --args vendor/hp/<model>/validity-sensor getver` |
| `perm.bin` | `scripts/dump_perm.gdb` (edit the output path), then it lands as `perm_<width>.bin` → rename to `data/<model>/perm.bin` |
| `dli_config.json` *(optional)* | `VFS_OUT=data/<model>/dli_config.json gdb -x scripts/dump_dli_config.gdb.py ...` |
| `init_seq.json` + `patches/` | parse the `06`/`1f` uploads out of `trace.usblog` |
| `capture_seq.json` | decrypt the in-session `17` records from the trace (below) |
| `client_cert.hex`, `client_privkey.json` | **VFS471 only** — dump the static client cert + RSA private key from the binary |

### VFS471 in-session sequence

`build_capture_seq_vfs471.py` decrypts HP's 471 session and lays its commands
into the 28-slot layout the driver expects:

```
python3 -I tools/build_capture_seq_vfs471.py \
    --trace vendor/hp/vfs471/trace.usblog \
    --secrets vendor/hp/vfs471/secrets.txt \
    --base <a VFS495 capture_seq.json to take the slot shape from> \
    --out data/vfs471/capture_seq.json
```

The VFS495 sequence is a straight dump of its plaintext in-session commands (no
re-slotting); the 495 does not need the client-cert files.

## 3. Verify

```
cargo build --release
./target/release/vfs495 --device <model> handshake   # expects "HANDSHAKE OK"
```

The driver auto-detects the model from USB, so once `data/<model>/` is populated
the daemon and all subcommands work without `--device`.
