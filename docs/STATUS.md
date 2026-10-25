# VFS495 open driver — project status & reverse-engineering reference

A distilled, organized digest of the project's established facts, the reverse
engineering of HP's binary, and the current state of the open driver. For the
chronological, dated reasoning and evidence behind every claim here, see
[`../NOTES.md`](../NOTES.md). For build and usage, see [`../README.md`](../README.md).

Status as of 2026-10-01: **the open secure session, transport, EP2 image decryption
and per-session calibration run in open Rust with no HP code, live on hardware.**
A feeder daemon bridges to libfprint for GNOME/fprintd. A user swipe now
yields a real fingerprint image (session 10; earlier "real print" / "enrolls +
verifies" claims from held-finger captures were noise self-matching). The
former blocker — the no-finger ridge baseline drifting into the finger range — is
fixed (session 10): calibration is now computed per session from our own sweep
frames (open ports of HP's step functions). Finger detection now gates on contact rows. Swipes are now
reconstructed at true scale from the sensor's second sensing line (session 11, HP's
method), and **live enroll + verify passes** (2026-10-04; every pair of that run's
six swipes matches, mean score 84 — §0).

**Image quality (2026-10-25):** the swipe reconstruction was shearing the print ~30°
and cropping it (grey wedge), which hurt matching. Cause: `reconstruct_swipe` integrated
a biased per-line lateral drift into a cumulative sideways shift. The raw decode itself
is straight and full (decode is correct). Fix: `VFS_LATERAL` (default `none`) drops the
lateral shift; prints now reconstruct upright, full-width and consistent swipe-to-swipe.
Re-enroll to benefit. See NOTES.md 2026-10-25.

**VFS471 port (2026-10-25):** this tree now drives the VFS471 (`138a:003c`). Its
in-session sequence must be the 471's own (`scripts/build_seq471.py`, from a decrypted
HP 471 trace): the 495 sequence's `0x06` patches reboot the 471 off USB, which was the
whole "imaging-latch re-enumeration". With 471 patches: no re-enumeration, prepare ~5 s,
~1.5–2 s per swipe; imaging is finger-gated by the sensor after `0x17`; a wedged sensor
(init refused / `2604`) is cleared with a USB port reset (HP's `palSensorHWReset`);
runtime calibration does not fit the 471 (`VFS_NO_CALIB=1`). Details: NOTES.md 2026-10-25.

---

## 0. Resume here (session 11, 2026-10-03)

**Where we are:** the no-finger drift blocker is **fixed**. Each capture session now
runs its own AFE calibration (`src/calib.rs`): the three steps whose results vary
(PgaOffset, Adc, PgaGain) are computed from our own sweep frames with byte-exact
ports of HP's step functions and carried into every later command, exactly as HP
does. Live, no finger, 7 sessions: computed PgaOffset=5, Adc=130–133, PgaGain=6 (the
same values HP picks) and **ridge_peak 1.07–1.25** (stale replay gave 1.6–2.7).

Two bugs fixed on the way:
- **EP2 line loss.** The reply wait alternated 20 ms on EP1 / 20 ms on EP2; the
  sensor's EP2 FIFO (~14 lines) overflowed during each EP1 wait and ~27 lines were
  dropped, corrupting every sweep frame (and the image stream). EP2 is now read by
  a scoped thread for the whole reply wait; sweep frames arrive gap-free.
- **Stale calibration replay** (the drift root cause, see NOTES 2026-10-01).

**MAJOR CORRECTION (session 10, after the user's finger test):** the fully-open
path has **never produced a real fingerprint image**. Finger held → ridge_peak 1.42
(marginal), and objectively every open-path image — old "finger" captures included —
has orientation coherence ~0.09 (pure noise) vs 0.87 for the HP-harvested print
(`captures/fingerprint_open.png`). So the earlier "real print", "finger ~2.1", and
"enrolls + verifies through libfprint" claims are falsified (noise self-matches).
See NOTES 2026-10-01 "CORRECTION".

**FIRST REAL PRINT FROM THE FULLY-OPEN PATH (2026-10-01):** a user **swipe**
through `vfs495 capture` decodes to a clear fingerprint (loop core), ridge
coherence 0.98 (HP's print 0.87–0.90, noise 0.09), 6258 contact rows (no finger: 0).
Root causes of the earlier "all noise" images: press-and-hold on a swipe sensor, and
`image::normalize` subtracting the per-column mean over ALL rows (erases a finger
held still). Decode was always correct; `06 06`/`07 07` headers are the PgaGain echo.

**Gate replaced:** the daemon/`ridge-probe` now gate on **contact rows**
(`--min-contact`, default 300; row sd ≥ 25 after a per-column-median background).
Live: no finger 0 rows (that same capture had ridge_peak 2.51 — the old gate would
have falsely fired). ridge_peak is printed as a diagnostic only. All prompts now say
SWIPE.

**Swipe reconstruction (session 10, superseded in session 11):** raw swipes were
~6-10x vertically stretched (the sensor scans faster than a finger moves). The first
fix kept a row once it differed enough from the last kept row; that gave each swipe
its own scale (see below). A touch without motion is refused by `run`/daemon. Cues
print exactly at each imaging window: "DON'T TOUCH" → "SWIPE ↓" → "WAIT" → "SWIPE ↓".

**Live enroll (2026-10-02):** 5/5 enroll stages accepted from 5 real swipes, but
**different swipes did not match** (offline leave-one-out on 6 saved swipes: 0/6
genuine; control self-match OK). Cause: the threshold de-stretch gave each swipe a
different vertical scale (pairwise 0.70-1.40).

**Session 11 (2026-10-03) — speed-true reconstruction (`src/swipe.rs`):** HP's
reconstructor was reverse-engineered and reimplemented. The sensor has a
**secondary sensing line 8 pixel rows (400 µm) upstream of the primary line** —
decoded columns 226..262 (inverted; column `c` sits over primary pixel `c-131`).
Correlating it against later primary lines gives the lag `L` the skin needs to
travel 8 rows, so the finger moves `8/L` rows per line; rows are resampled at that
rate, one per 50 µm, with lateral drift corrected too (details §4, NOTES 2026-10-03).
Results on the recorded swipes (HP's 5 + 1 live; `captures/swipe_*.bin`):
- natural-looking 200x157-226 prints; same-finger swipes now agree in vertical scale
  to 0.965-1.04 (was 0.70-1.40); mean isotropy 0.99 (was 1.33).
- libfprint genuine scores (bozorth3, match >= 40), leave-one-out over the 4
  same-finger HP swipes: **3-9 before -> 11-27** with the new reconstruction plus a
  1.5x enlargement before feeding (`image::FEED_SCALE`); impostors stay <= 7.
  **Still below 40** — but these 4 swipes are fingertip-only partials with little
  overlap, so this is not the final word. The 6 full-pad live swipes of 2026-10-02
  cannot be re-run (their raw streams were not saved; they are saved now).

**Live enroll run 3 (2026-10-03, new reconstruction): first genuine cross-swipe
matches.** Six full-pad live swipes (`captures/swipe_live2_*.bin`), offline
leave-one-out: **4 of 6 held-out swipes match** (best scores 40, 57, 57, 40; threshold
40), impostor max 16. The two failures are poor swipes (one stalled mid-swipe and
smeared, one started below the core — that one was the live verify). Margin is thin.

**Margin work (2026-10-03, same data):** sub-pixel lateral drift + masking the
non-finger background (both in `src/swipe.rs`) raise the leave-one-out best scores from
40/57/57/40 to **44/97/95/45** (still 4 of 6 swipes); pairwise mean 21.7 -> 26.2
(`scripts/pair_scores.py`), impostors <= 10. The two failing swipes fail on **finger
placement** (one 3.7 mm off to the side, one started below the core), not on
reconstruction. Rejected with numbers in NOTES: Gabor enhancement, other enlargement
factors, fixed/constant lateral drift, global rescale, stall trimming.

**FIRST LIVE PASS (run 4, 2026-10-04):** `live_enroll.py` enrolled 5 swipes and the
live verify matched. Offline on its six swipes (`captures/swipe_live3_*.bin`): 30 of 30
pairs >= 40 (mean 84, min 41), impostors <= 10. Cross-session: a template from run 4
matches 4 of run 3's 6 sloppier swipes (the other two score 37 and 16: one started
below the core, one was 3.7 mm off to the side); a template from run 3 matches 6 of 6
of run 4. Speed and angle differences are handled; a swipe showing a mostly different
part of the finger than anything enrolled still fails.

**User requirement:** must tolerate sloppy placement/angle/speed like a normal sensor.

**System integration (2026-10-04, in progress — see `docs/SYSTEM_CHANGES.md`):** the
daemon now captures only while fprintd reports `finger-needed` (an open device is not
enough: GNOME Settings claims it just by showing its dialog), and lights the Caps Lock
LED during the swipe windows (first window ~9 s after the request, cycle 22 s). Binary,
data, `vfs495.service` and the fprintd drop-in are installed; fprintd lists the device.
The SELinux module `vfs495_fprintd` (needed so fprintd can create the socket) was
loaded by the user. Verified without a finger: `fprintd-enroll` claims the device, the
daemon captures on that request and reports "no usable swipe", no AVC denials.
First `fprintd-enroll` (2026-10-04): 4 stages passed from real swipes, then libfprint's
generic overheating model cut it off (device active ~3 min; 23 s per capture cycle was too
slow). Now the daemon calibrates once per request (~9 s) and then repeats imaging windows
(~4 s each, LED lit ~3 s of it) with no recalibration — verified without a finger
(8/8 windows full), **not yet with a finger**.
**Waiting for the user:** `fprintd-enroll` again, `fprintd-verify`, then `sudo` in a new
terminal.

**NEXT ACTION after that:** (a) shorten the 9 s calibration wait before the first
window (calibrate ahead of time?); (b) tolerance to partial overlap: a real libfprint driver (own match threshold, proper
retry, and no SELinux module needed) and/or more varied enrolment; (c) swipe 6's ~14%
vertical stretch; (d) HP's `IRfinalize*Estimates`.

**Sensor access note:** the udev rule is installed (`user:bine:rw-`); it survives
re-enumeration. If the sensor gets wedged, a full power-off (not just reboot) clears
its state. Back-to-back `ridge-probe` runs can still re-enumerate (per-run session;
diagnostic only) — space them a few seconds apart.

---

## 1. Target and constraints

- **Sensor:** Validity VFS495 ("Falcon"), USB `138a:003f`, HP EliteBook 820 G3
  and other 2015-era HP laptops. `bcdDevice 1.04`. Endpoints: EP1 IN/OUT bulk 64,
  EP2 IN bulk 64 (image), EP3 IN interrupt 8.
- **Repo:** git at `~/Developer/lab/vfs495`, remote `origin`
  (github.com/hammadmajid/vfs495). HP's package and all extractions live in
  `vendor/` (gitignored, never committed). Biometric captures, raw USB traces, and
  HP patch blobs are also gitignored — keep them out of commits since the repo is
  published.
- **Do not**, without explicit user OK: send `TakeOwnership` / `setowner` /
  `resetowner` (persistent, cycle-limited sensor writes), or change system
  fprintd / PAM / authselect / GDM config.

---

## 2. Key established facts

### Secure session (SSLv3-RSA)
- The sensor wraps every command in a **proprietary variant of SSLv3-RSA**
  (cipher suite `0x0044` = AES-256-CBC + SHA-1).
- Prior art (saifulmd0/vfs495-linux) hit fatal alert **`0x2f`** because on an
  **owned** sensor the `ClientKeyExchange` wraps the premaster secret in
  `AES-256-CBC(s_key)` before RSA, where `s_key` is a 32-byte DH-derived shared
  secret set at pairing.
- **This sensor is UNOWNED** (`get_ownership_info` → 65535/65535 cycles left). On
  an unowned sensor the `s_key` wrap is skipped, so a **standard open SSLv3
  client establishes the session with no pairing at all** — the wall every prior
  VFS495 project hit. Proven live in Rust (`vfs495 handshake` → CCS + Finished,
  no alert).
- The sensor's RSA pubkey (2048-bit, `e=65537`) modulus is in
  `captures/modulus.json`. The sensor ships the pubkey in an opaque signed key
  blob on EP2 during init (no clean TLV/length anchor → kept file-based per
  device; dump with `scripts/dump_modulus.gdb.py`).

### Pairing (not needed here, fully mapped)
- **Pairing = "TakeOwnership"**: cmd `0x0f` (DH → `s_key`) + cmd `0x2c` (host RSA
  keypair). Reversible via `ResetOwnership`; 65535 ownership cycles. Credentials
  are stored host-side in `/etc/ValidityPersistentData` (GSKGlobal-wrapped),
  keyed by sensor serial. Not implemented — this sensor is unowned.

### Reply format
- In-session replies are plain SSLv3 AppData records (`17 03 00 <len> <ct>`) on
  EP1 — no tunnel (the `0x11` tunnel is handshake-only). Decrypted reply
  plaintext = **`u16 LE status` + optional payload**. `0x0000` / `0x0412` = OK;
  any status with bit `0x0400` set = error. A bare ack is 2 bytes (`00 00`).
- The earlier "capture is a blocked, un-replayable interactive protocol"
  conclusion was an artifact of misparsing the 2-byte status ack. The polls work.

### Capture command stream
- Capture is driven by replaying HP's in-session command sequence
  (`captures/capture_seq.json`, gitignored device data; a list of plaintext
  command-hex strings extracted from an HP `scsSend` trace). Each command is
  re-encrypted with **our** session keys — no HP ciphertext is reused.
- 42-command sequence: `1f` setup; calibration block (`1a`/`06`/`02` sweep
  frames, ~idx 0–15, term `0x12`); then the poll/imaging loop (`0x02` polls,
  then `0x17`/`0x04` imaging latch, then `0x02` imaging bursts).
- Commands `0..23` all return status `0x0000` OK on a clean session.

---

## 3. The EP2 image transform (the final unlock)

The raw EP2 imaging stream is **AES-256-CBC encrypted** (entropy ~8, no SSL
framing). The frames that decode to a fingerprint (`01fe`-framed, 272-byte
stride) only appear *after* decryption. This is what made a raw live capture
show "too few lines" until session 5.

- **Cipher:** `scsSensorDecryptFingerprint@0x4fd640` → `palCryptoAesCbc`. IV
  chains across EP2 reads (last 16 ciphertext bytes → next IV); decrypt is
  in-place. Key length comes from the SSL suite (=32).
- **Key source:** NOT the SSL session key. HP generates a **fresh random 32-byte
  key and IV per capture** in `_scsSensorFpEncInit@0x4eb7f0` (`palCryptoRng`).
- **Key delivery:** `scsGetSecurityParams@0x4fd740` packs them **in the clear**
  (no RSA wrap) into a SecurityParams TLV embedded in the `0x02` GetFingerprint
  command, sent inside the already-SSL-encrypted channel:

  | field | offset in TLV value | size |
  |-------|--------------------|------|
  | AES-256 key | `0x00` | 32 |
  | IV (16 used) | `0x20` | 32 |
  | sign/HMAC key | `0x40` | 32 |
  | cipher selector (`0x04` = AES-256) | `0x68` | 1 |

  TLV header = tag `0x0006` (LE) + length `0x6a` (LE), i.e. `06 00 6a 00`.

- **Why replay works:** we replay HP's exact command bytes, so the sensor
  encrypts EP2 with HP's key — which is sitting in plaintext in those same bytes.
  We read it back and decrypt. In `capture_seq.json`, commands `3/17/22/23/26/27/41`
  carry the TLV; imaging commands `23` and `27` also carry a populated sign key.
- **Proven:** decrypting the imaging burst with the command's key yields clean
  `01fe` frames at 272 stride (frame-type `07 07`; the `06`/`07` byte is a mode
  marker the open unpack ignores) → a real fingerprint. Wrong key → noise.
- The image **signature** (sign key + `_scsSensorFpSignUpdate`) is an integrity
  HMAC over the image; not needed to obtain pixels, currently ignored.

---

## 4. Image decode (open, byte-exact)

`src/image.rs` is a clean-room reimplementation of HP's `UnpackLineRT`
(`0x46f510`) plus line assembly and reconstruction:

- **Modes:** mode 8 = `dst[perm[i]] = src[i]` (8-bit direct + descramble scatter);
  mode 4 = nibble expand; general = variable-bit per-column (bits at `cfg+8`,
  left-justify `<< (8-w)`, perm scatter at `cfg+0x57c`).
- **This device:** main image frames are **mode 8, width 264**, on-wire `01fe` +
  8-byte header + 264 payload = **stride 272**. Descramble table
  `captures/perm_264.bin` = `reverse(0..199) ++ reverse(200..263)`.
- **Config** (`captures/dli_config.json`) confirmed on-device with
  `scripts/dump_dli_config.gdb.py` (mode 8, width 264, max_bits 8; perm is a
  valid permutation of 0..263).
- **Verified byte-exact:** `scripts/dump_unpack_pairs.gdb.py` — the open
  `dst[perm[i]] = src[i]` unpack reproduces HP's `UnpackLineRT` output on 95/95
  real image lines, 0 mismatches.
- (The table is not quite two plain reversals: source 242 maps to column 263, so
  sources 200..241 land on 262..221 and 243..263 on 220..200.)
- **Line layout (flex id 0x13, `gFlexInfo` entry @0x86d360):** columns 0..199 =
  primary line (200 px, 50 µm pitch, 508 dpi); columns 200..263 = 64-slot
  **secondary line**, 400 µm (8 rows) upstream, stored inverted. Live secondary
  columns: 226..262 minus 240, 250; column `c` sits over primary pixel `c-131`
  (data-fitted; HP's `SecToPriMap_VFS4xx_12A` says slot+68, i.e. within a pixel).
  The 8-byte line header is `01 fe`, u16 line counter, PgaGain echo, a periodic
  0x10 flag — no motion or timestamp data.
- **Swipe reconstruction (`src/swipe.rs`, HP's IR model):** per contact run —
  1. cull static lines (HP `vcsCullScanLine` first test: keep a line once >= 2 of
     primary pixels 10..189 differ from the last kept line by > 25);
  2. windowed NCC (31 lines) of secondary(t) vs primary(t±L), L = 2..160 culled
     lines, lateral shift -3..3; direction = the better-correlating sign;
  3. Viterbi-track the lag, parabola-refine it; accept a lag only if NCC >= 0.5,
     the secondary is on skin, and it is an interior peak (L >= 4, NCC halfway to
     zero lag lower by >= 0.15 — rejects ridges parallel to the swipe / resting finger);
  4. hold the nearest accepted lag up to 1.5·L lines away, emit nothing beyond;
  5. lateral drift dx at sub-pixel precision (NCC vs shift -5..5 at the tracked lag,
     parabola peak, median 31 + mean 61);
  6. position y = Σ 8/L, x = Σ dx/L; interpolate the primary line at integer y;
  7. non-finger background (reachable from the border) flattened to mid-grey.
  HP instead quantises the lag to 1..21 and inserts/deletes whole lines
  (`dutyCycleInsDelSep8` @0x542240, `retInsDelSep8` @0x542280); `vcsInitIR`
  requires separation/pitch == 8. Not ported: HP's further cull tests,
  `IRfinalizeYlag/XlagEstimates` smoothing, `IRpostProcessImage`.
- Before feeding libfprint the image is enlarged 1.5x (`image::FEED_SCALE`) and
  clamped to 500 rows. `vfs495 decode --feed` writes exactly that image.
- Falsified (2026-10-03): the "beaded" look of horizontal ridges is **not** an
  even/odd staggered pixel layout — adjacent-column time lags show no parity
  pattern (even 2.0 / odd 2.0 lines).

---

## 5. Reverse-engineered HP functions (binary has debug symbols)

`vendor/runtime/bin/validity-sensor-unlocked` (built by
`scripts/build_harness.sh` with OpenSSL-0.9.8 stubs; not stripped).

| function | addr | role |
|----------|------|------|
| `scsSend` | `0x4f7bd0` | VCSFW wire framing `[cmd byte][payload]` |
| `scsSensorSendGetFingerprint_V4` | `0x5065f0` | builds the `0x02` poll/capture command |
| `scsSensorParseReply_V4` | `0x506340` | reply status decode (LE) |
| `idsSensorWOEFingerprintPoll` | `0x456320` | WOE finger-poll loop (poll-then-watch) |
| `scsSensorFalconCalibrate` | `0x4fcb20` | closed-loop calibration (data-dependent) |
| `scsSensorDecryptFingerprint` | `0x4fd640` | AES-256-CBC EP2 image decrypt |
| `_scsSensorFpEncInit` | `0x4eb7f0` | RNG-generate per-capture image key + IV |
| `scsGetSecurityParams` | `0x4fd740` | pack key/IV into the SecurityParams TLV |
| `irDliRTFalconData` | `0x462350` | frame demux/assembly (scans `01fe`) |
| `UnpackLineRT` | `0x46f510` | line unpack/descramble |
| `idsSensorPickImageReconstructor` | `0x454dd0` | → `idsStartupIr` → `irDliRTStartup` (flex +0x14 = 4) |
| `ProcessTimeslotTable` | `0x46f1c0` | builds the unscramble table (200 primary + 64 secondary) |
| `vcsDoIR` | `0x463060` | per line: parse header, cull, `IRprocessScanline` |
| `vcsCullScanLine` | `0x471660` | drops lines where the finger has not moved |
| `IRprocessScanline` | `0x46aac0` | inverts secondary pixels, `IRcorrelateUp/Down` (lag search) |
| `setupCorrParams` | `0x463f10` | lag search window |
| `vcsInitIR` | `0x4639xx` | base lag = separation/pitch, must be 8 |
| `IRreconstructImage` | `0x468ff0` | lag → line insert/delete, x-lag offset, post-process |

HP tracing harness verbs: `getver`, `get_ownership_info`, `getprintwait`,
`setowner` (writes!). Always `-doinit`.

---

## 6. Rust driver (crate `vfs495`, MIT, at repo root)

| module | responsibility |
|--------|----------------|
| `src/crypto.rs` | SSLv3 KDF, RSA (LE modulus, PKCS#1 v1.5), length-less MAC, AES-256-CBC record layer, `decrypt_image_stream` (EP2). Byte-exact vs `captures/skey_dump.json` (`vfs495 selftest`). |
| `src/usb.rs` | libusb transport (rusb): EP1 OUT/IN, EP2 image; `read_record` / `read_record_split`; kernel-driver detach/reattach. |
| `src/session.rs` | init replay + open SSLv3 handshake → active record layer. |
| `src/capture.rs` | in-session command replay, EP2 decrypt, `arm_capture` (full imaging capture → decrypted stream), `poll_probe` diagnostic. |
| `src/image.rs` | `UnpackLineRT` port, descramble, assembly, contact gate, feed enlargement → PGM; `ridge_peak` (diagnostic). |
| `src/swipe.rs` | swipe reconstruction at true scale from the secondary sensing line (§4). |
| `src/virtimage.rs` | feed a decoded image to `$FP_VIRTUAL_IMAGE`. |
| `src/main.rs` | CLI: `selftest`, `handshake`, `capture`, `poll-probe`, `ridge-probe`, `decode`, `decode-lines`, `feed`, `run`, `daemon`. |

Toolchain: `libusb1-devel`; non-root USB via `packaging/70-vfs495.rules`.
16 unit tests pass.

### Transport fix (session 4)
The `0x17`/`0x04` imaging latch made EP2 stream data; blocking on an EP1 reply
while EP2 was undrained starved the FIFO and reset the sensor (`-108`), which
looked like a USB re-enumeration. The fix interleaves EP2 draining with the EP1
reply wait (`read_record_split`, `drain_image_bounded`, `read_reply_interleaved`,
`send_cmd_draining`). Live result: all 42 commands OK, no reset, stable USB
address. (The old "the imaging latch re-enumerates the sensor" premise was false
— HP images a full swipe on one stable address; the old usblog "R(err)" were EP2
read cancels, not USB resets.)

### Falsified hypotheses (with evidence, so we don't revisit)
- `set_active_configuration` on reopen — the kernel sets config anyway.
- HP vendor control-plane resume on reopen — none; all standard kernel/hub
  enumeration.
- resend-`0x04` / SSL seq-continuity across a reset — the session was genuinely
  gone (zeros, not an alert). Moot once the re-enum was shown to be our bug.

---

## 7. Feeder daemon and GNOME integration

`vfs495 daemon` bridges the open capture path to libfprint's `virtual_image`
driver, so the sensor works through stock **fprintd / PAM / GDM / sudo** with no
custom C driver. The enroll → match → reject round-trip through libfprint is
proven in `scripts/vimage_proof.py`.

**Finger detection — ridge gate (the sensor streams high-variance imaging noise
even with no finger, so contrast, line count, and the segmentation crop all fail
to gate; only the ridge spectral peak works).** Each cycle the daemon fires a full
imaging capture (`arm_capture`), decodes it, and accepts it as a finger iff the
reconstructed image's **ridge spectral peak-to-mean** clears `--min-ridge`. That
is the sole gate. Measured live 2026-09-28 with the `ridge-probe` diagnostic:

| capture | ridge_peak | crop_ratio | verdict @1.4 |
|---------|-----------|-----------|--------------|
| no finger | **1.21** | 0.857 | reject ✓ |
| finger (held) | **2.10** | 0.995 | accept ✓ |

- `ridge_peak` separates cleanly (noise ~1.1–1.2, finger ~1.8–2.1); the default
  `--min-ridge 1.4` sits between them.
- `crop_ratio` is **not** a finger signal and was removed from the gate: a held
  finger covers nearly every line, so segmentation crops nothing (0.995 > the
  no-finger 0.857 — the wrong direction). It is logged for diagnostics only.
- Firing the imaging latch every cycle is safe (the "latch stresses the sensor"
  premise was falsified in §6, and HP images full swipes on one stable address).

Diagnostic: `vfs495 ridge-probe [--min-ridge N]` — captures, decodes, prints
`ridge_peak`/`crop_ratio`/line count and the daemon verdict without gating, and
writes a PGM. Run once with a finger and once without to compare / retune.

**Falsified and removed (2026-09-28): the WOE poll-divergence gate.** The former
`capture::capture_on_finger` polled `seq[17]` (0x02 GetFingerprint) and watched for
reply divergence from a no-finger baseline. Live test with a finger held firmly the
entire run showed that poll is **finger-blind**: reply byte-divergence stayed flat
at `nd = 2–4` and the pre-latch EP2 stayed a constant 5712 B at mean ≈127 / sd ≈74,
identical with and without contact. Replaying a captured poll returns a canned
reply plus free-running AFE noise; without the `0x17`/`0x04` imaging latch there is
no finger signal. The old "~10 byte baseline jitter" was measuring that noise. The
poll path, `--contact-nd`, and `--max-wait-polls` were deleted. If a low-power gate
is wanted later (to avoid imaging on empty cycles), investigate the **unused EP3
interrupt endpoint** or a dedicated WOE command — not a replayed swipe poll.
(`vfs495 poll-probe` remains as a diagnostic; its defaults were corrected to
`--prefix 17 --poll-idx 17` — index 16 is a `0x06` calibration command with a
constant reply and no EP2, the earlier off-by-one that read all zeros.)

Tunables: `--min-ridge` (1.4), `--gap`, `--once`. `VFS_NO_PROMPT=1` suppresses the
interactive capture prompt.

**To route the system fprintd through the bridge** (a system-config change the
user must opt into), add a systemd drop-in setting `FP_VIRTUAL_IMAGE` and run the
daemon — see the README "GNOME / fprintd integration" section.

---

## 8. Current status and remaining work

**Done and live-confirmed:**
- Open SSLv3 session and transport (no HP code in the session path).
- Full command replay with continuous EP2 draining, no sensor reset.
- AES-256-CBC EP2 image decryption (key recovered from the replayed command).
- Open decode + reconstruction → real fingerprint (264×623, ridge ~10.6 px).
- libfprint enroll/verify through `virtual_image` proven (`vimage_proof.py`).
- **Finger detection: ridge-peak gate, live-confirmed** (finger 2.10 vs no-finger
  1.21, threshold 1.4). Daemon rebuilt on it; the finger-blind WOE poll gate and
  the misleading crop-ratio condition were removed. See §7.
- **Our live capture enrolls and verifies through libfprint** (2026-09-28): a real
  live-path image (ridge_peak 2.10) enrolls all 5 stages, matches itself, and
  rejects a different print, driving libfprint directly via GObject introspection
  (same path as `vimage_proof.py`, no fprintd/PAM change). So the sensor's image
  contains genuine, usable minutiae.

**Image-size fix (2026-09-28):** libfprint rejects an over-tall image
("unrealistically large image, disconnecting client") *before* reading minutiae. A
**held** finger stacks the same region into a huge redundant strip (264×7867 in the
test) and was rejected outright; a normal finger-sized window of the same capture
enrolls/verifies fine (264×400 and 264×500 both PASS). `reconstruct` now clamps the
finger band to a central `MAX_FEED_ROWS` (500) window, so the daemon always feeds a
libfprint-acceptable, minutiae-friendly image. (A swipe assembles to a few-hundred
-line band and is unaffected; the clamp only bites the held-finger case.)

**Remaining:**
- **Re-confirm the finger-side ridge_peak** with the fixed stream + per-session
  calibration (no-finger is now 1.07–1.25 stably; finger was ~2.1 under the old,
  stale/gappy path). The old drift blocker is FIXED (session 10, §0): it was 4 stale
  calibration values in the replay, now computed per session in `src/calib.rs`.
  NOTE: `ridge_peak` is window-size dependent — it MUST be computed on the full
  image; `window_for_feed` clamps only the pixels sent to libfprint, after the gate.
- End-to-end **live** daemon enroll/verify with touches — unblocked; next. The image *substance* is proven (a real live capture enrolls all 5 stages
  and verifies through libfprint).
- fprintd systemd drop-in for `FP_VIRTUAL_IMAGE` — a user-opt-in system change.

**Done this session (10):**
- Per-session AFE calibration (`src/calib.rs`): byte-exact ports of
  `scsFalconCalPgaOffset` / `scsFalconCalAdc` / `scsFalconCalPgaGain`, each
  verified against 5 HP ground-truth runs (and HP's internal sum tables), with
  HP-style sweep-frame validation; results carried into later commands (47 sites).
- EP2 read on a scoped thread during reply waits — fixes ~27-line drops per gap.

**Done session 9:**
- **Session reuse fixes the re-enumeration.** The daemon opens + handshakes once
  and reuses the session across captures (rebuilding on a fault); 6 back-to-back
  no-finger cycles ran with 0 errors and a stable USB address. (`ridge-probe` still
  opens per-run, so repeated ridge-probes re-enumerate — diagnostic-only.)
- Fixed the `MAX_FEED_ROWS` clamp that broke the gate (it made `ridge_peak` be
  computed on the 500-row feed window, inflating no-finger to ~2.5). Gate is on the
  full image again; `window_for_feed` clamps only the fed pixels.
- Verify the open unpack is byte-exact for frame-type `07` (payload decodes to
  ridges, so almost certainly yes).
- Optional: a low-power gate via the unused **EP3 interrupt endpoint** to avoid
  imaging on empty cycles (currently every cycle images then gates on the picture).
- Owned-sensor pairing is mapped but unimplemented (not needed here).
- Per-device RSA modulus auto-extraction is not wired (dump per unit).

---

## 9. Diagnostic env gates (in the driver)

`VFS_NO_PROMPT` (suppress the DO NOT TOUCH / SWIPE NOW cues),
`VFS_SAVE_FED=<dir>` (`run` keeps each fed image + decrypted stream),
`VFS_SWIPE_DEBUG` (print per-run cull/lag statistics of the swipe reconstruction),
`VFS_SKIP_17`, `VFS_NO_REHANDSHAKE`, `VFS_REOPEN_SETCONFIG`, `VFS_HP_RESUME`,
`VFS_DUMP_SLICES=<dir>` (write each command's raw EP2 slice as `NN_raw.bin`;
calibration sweep frames are idx 6..12, plaintext), `VFS_NO_CALIB` (replay the
recorded calibration values instead of computing them — A/B diagnostic).
Most are leftovers from the re-enumeration investigation and are inert on the
happy path; kept for regression probing.
