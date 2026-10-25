# Per-model runtime data

The driver loads everything device-specific from `data/<model>/`, where `<model>`
is the sensor's short name (`vfs471`, `vfs495`). The driver selects the directory
automatically from the USB product ID (or `--device <model>`).

**None of these files are committed.** They are all derived from HP/Validity's
proprietary driver (firmware patches, the sensor's RSA key, the client
certificate and private key, the descramble table, the command sequences), so
they are gitignored. Generate them with the scripts in [`../tools/`](../tools/)
from an HP package placed under `vendor/hp/<model>/` (also gitignored).

## Files per model

| File | What it is | Source |
| --- | --- | --- |
| `init_seq.json` | Power-on patch-upload + flash-read sequence | HP USB trace |
| `patches/*.bin` | HP firmware patch blobs referenced by `init_seq.json` | HP USB trace |
| `modulus.json` | The sensor's RSA public key (little-endian modulus, exp) | HP binary (gdb) |
| `capture_seq.json` | In-session command sequence (plaintext hex per command) | HP USB trace |
| `perm.bin` | 264-entry descramble permutation (LE `i16`) | HP binary (gdb) |
| `dli_config.json` | *(optional)* decode config; sensible defaults if absent | HP binary (gdb) |
| `client_cert.hex` | Static client Certificate handshake message (`0x0b`) | HP binary — **VFS471 only** |
| `client_privkey.json` | Client RSA private key for CertificateVerify | HP binary — **VFS471 only** |

The VFS495 handshake is plain RSA and needs no client certificate, so its
`client_cert.hex` / `client_privkey.json` are not used.

See [`../tools/README.md`](../tools/README.md) for how to produce these.
