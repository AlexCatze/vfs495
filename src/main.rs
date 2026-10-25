//! `vfs495` — command-line driver for the Validity "Falcon" family (VFS495,
//! VFS471) of fingerprint sensors.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vfs495::device::{Device, Lateral};
use vfs495::{capture, crypto, image, session, swipe, usb, virtimage};

#[derive(Parser)]
#[command(name = "vfs495", version, about = "Open userspace driver for the Validity Falcon family (VFS495/VFS471)")]
struct Cli {
    /// Base directory holding data/ (defaults to the current dir).
    #[arg(long, global = true, default_value = ".")]
    base: PathBuf,

    /// Sensor model (vfs471, vfs495). Auto-detected from USB when omitted.
    #[arg(long, global = true)]
    device: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

/// Resolve the sensor profile: `--device` if given, else the one on the USB bus.
fn resolve_device(cli: &Cli) -> Result<&'static Device> {
    match &cli.device {
        Some(name) => Device::by_name(name)
            .ok_or_else(|| anyhow::anyhow!("unknown --device '{name}' (expected vfs471 or vfs495)")),
        None => usb::detect()
            .ok_or_else(|| anyhow::anyhow!("no supported sensor on USB; pass --device vfs471|vfs495")),
    }
}

#[derive(Subcommand)]
enum Command {
    /// Offline crypto self-test (no hardware). Validates the SSLv3 KDF byte-exact.
    Selftest,
    /// Live: replay init and run the open SSLv3 handshake, then exit.
    Handshake,
    /// Live: handshake, capture one swipe, and write a raw EP2 dump.
    Capture {
        /// Where to write the raw EP2 byte stream.
        #[arg(long, default_value = "captures/ep2_stream.bin")]
        out: PathBuf,
    },
    /// Live diagnostic: reach poll-ready state, then loop the poll command and dump
    /// each reply payload so a finger touch reveals the finger-contact signal.
    /// Never fires the imaging trigger, so the sensor does not reset.
    PollProbe {
        /// How many leading sequence commands to replay to reach poll-ready state.
        /// Must match the poll: replay 0..poll_idx, then loop seq[poll_idx].
        #[arg(long, default_value_t = 17)]
        prefix: usize,
        /// Which sequence index to loop. Defaults to 17, the 0x02 GetFingerprint
        /// poll the daemon watches (capture::POLL_IDX). Index 16 is a 0x06
        /// calibration command with a constant reply — do not probe that.
        #[arg(long, default_value_t = 17)]
        poll_idx: usize,
        /// How many poll iterations to send.
        #[arg(long, default_value_t = 40)]
        iters: usize,
    },
    /// Live diagnostic: fire a full imaging capture, decode it, and print the
    /// finger-gate metric (contact rows) plus diagnostics and the daemon's
    /// accept/reject verdict — WITHOUT gating, so both a finger and a no-finger
    /// capture produce output. SWIPE a finger when prompted (this is a swipe
    /// sensor; a finger held still does not image).
    RidgeProbe {
        /// Contact-row threshold to report a verdict against (matches the
        /// daemon's --min-contact).
        #[arg(long, default_value_t = DEFAULT_MIN_CONTACT)]
        min_contact: usize,
        /// Also write the reconstructed image here for visual inspection.
        #[arg(long, default_value = "captures/ridge_probe.pgm")]
        out: PathBuf,
    },
    /// Decode a raw EP2 dump into a PGM (unpack + descramble + reconstruct).
    Decode {
        /// Raw EP2 byte-stream input.
        #[arg(long)]
        input: PathBuf,
        /// Output PGM path.
        #[arg(long, default_value = "captures/decoded.pgm")]
        out: PathBuf,
        /// Frame stride in bytes.
        #[arg(long, default_value_t = 272)]
        stride: usize,
        /// Keep the full frame instead of cropping to the finger band.
        #[arg(long)]
        no_crop: bool,
        /// Write the image exactly as `run`/`daemon` would feed it to libfprint.
        #[arg(long)]
        feed: bool,
    },
    /// Decode already-descrambled scan lines (`<u16 w><w bytes>` records) to PGM.
    /// Fully-open path from UnpackLineRT output to a fingerprint image.
    DecodeLines {
        /// lines.raw-format input.
        #[arg(long)]
        input: PathBuf,
        /// Output PGM path.
        #[arg(long, default_value = "captures/decoded.pgm")]
        out: PathBuf,
        /// Crop to the finger-present band (off by default; lines.raw is already finger data).
        #[arg(long)]
        crop: bool,
    },
    /// Send a PGM image to the libfprint virtual_image socket ($FP_VIRTUAL_IMAGE).
    Feed {
        /// PGM image to send.
        #[arg(long)]
        image: PathBuf,
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Live end-to-end: handshake → capture → decode → feed virtual_image.
    Run {
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Run continuously as a feeder: capture on each finger touch, decode, and
    /// push the image to libfprint's virtual_image socket so fprintd/PAM/GDM can
    /// enroll and verify. Idle cycles (no finger) are skipped quietly.
    /// Diagnostic: calibrate once, then open N imaging windows back to back and
    /// print what each returned (tests window repetition without recalibration).
    WindowTest {
        #[arg(long, default_value_t = 6)]
        count: usize,
        /// Save each window's decrypted EP2 stream to `<dir>/winNN.stream` (feed
        /// to `decode` offline for raw vs. reconstructed images).
        #[arg(long)]
        dump: Option<std::path::PathBuf>,
    },
    Daemon {
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
        /// Minimum number of finger-contact rows (row sd >= 25 after removing the
        /// fixed column pattern) to accept a capture as a finger. Measured live:
        /// no finger 0, a swipe ~6000 (HP's recorded swipes ~3900).
        #[arg(long, default_value_t = DEFAULT_MIN_CONTACT)]
        min_contact: usize,
        /// Capture a single frame and feed it, then exit (for testing).
        #[arg(long)]
        once: bool,
        /// Seconds to wait between capture cycles.
        #[arg(long, default_value_t = 1)]
        gap: u64,
        /// The socket belongs to the system fprintd: capture only while fprintd
        /// reports that it is waiting for a finger (an enroll/verify in progress),
        /// not merely while the device is open.
        #[arg(long)]
        fprintd: bool,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    // Selftest is pure crypto and needs no sensor; everything else needs a model.
    if matches!(cli.cmd, Command::Selftest) {
        let ok = vfs495::selftest(&cli.base)?;
        println!("\n=== SELFTEST: {} ===", if ok { "PASS" } else { "FAIL" });
        std::process::exit(if ok { 0 } else { 1 });
    }
    let device = resolve_device(&cli)?;
    let cfg = session::Config::for_device(&cli.base, device);

    match cli.cmd {
        Command::Selftest => unreachable!("handled above"),
        Command::Handshake => {
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            session::close(&dev, &mut rec);
            println!("[+] handshake OK — secure session established (and closed)");
        }
        Command::Capture { out } => {
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            let stream = capture::arm_capture(&mut dev, &mut rec, &cfg);
            session::close(&dev, &mut rec);
            let stream = stream?;
            std::fs::write(&out, &stream)?;
            println!("[+] wrote {} decrypted image bytes to {}", stream.len(), out.display());
        }
        Command::PollProbe { prefix, poll_idx, iters } => {
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            let probed = capture::poll_probe(&mut dev, &mut rec, &cfg, prefix, poll_idx, iters);
            session::close(&dev, &mut rec);
            probed?;
            println!("[+] poll-probe done");
        }
        Command::RidgeProbe { min_contact, out } => {
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            // Fire the full imaging sequence (same path the daemon arms on a
            // detected finger) and decode it, exactly as the daemon's gate does.
            let stream = capture::arm_capture(&mut dev, &mut rec, &cfg);
            session::close(&dev, &mut rec);
            let stream = stream?;
            let dli = image::DliConfig::load_main(&cfg.data_dir)?;
            let lines = image::decode_ep2(&stream, 272, &dli);
            println!(
                "[i] decrypted {} EP2 bytes -> {} decoded lines x {} cols",
                stream.len(),
                lines.rows,
                lines.cols
            );
            if lines.rows == 0 {
                bail!("no lines decoded — capture produced no frames");
            }
            let (gate, contact) = finger_gate(&lines, min_contact);
            let swipe = swipe::reconstruct_swipe(&lines, device.lateral());
            let verdict = gate && swipe.is_some();
            let (px, w, h) = swipe.unwrap_or_else(|| image::reconstruct(&lines, true));
            let ridge = image::ridge_peak(&px, w, h);
            println!("[i] reconstructed image: {w}x{h} ({})", if verdict { "swipe" } else { "no usable swipe" });
            println!("[i]   contact rows = {contact}   (THE gate — no finger 0, swipe thousands; gate >= {min_contact})");
            println!("[i]   ridge_peak   = {ridge:.2}   (diagnostic only — NOT a finger signal)");
            println!(
                "[{}] daemon verdict: {}",
                if verdict { "+" } else { "-" },
                if verdict { "FINGER (would feed)" } else { "no finger (would skip)" }
            );
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} for visual inspection", out.display());
        }
        Command::Decode { input, out, stride, no_crop, feed } => {
            let raw = std::fs::read(&input)?;
            let cfg = image::DliConfig::load_main(&cfg.data_dir)?;
            let lines = image::decode_ep2(&raw, stride, &cfg);
            println!("[i] unpacked {} lines x {} cols", lines.rows, lines.cols);
            if lines.rows < 20 {
                bail!("too few lines ({}) — not a usable swipe", lines.rows);
            }
            let mut sd = lines.contact_sd();
            sd.sort_by(|a, b| a.partial_cmp(b).unwrap());
            if let (Some(lo), Some(hi)) = (sd.get(sd.len() / 10), sd.get(sd.len() * 9 / 10)) {
                println!(
                    "[i] contact sd p10={lo:.1} p90={hi:.1}; rows with contact (sd>=25): {}",
                    lines.contact_rows(25.0)
                );
            }
            let (px, w, h) = match (no_crop, swipe::reconstruct_swipe(&lines, device.lateral())) {
                (false, Some(img)) => img,
                (false, None) => {
                    println!("[!] no usable swipe (finger moving across the sensor); writing the raw band");
                    image::reconstruct(&lines, true)
                }
                (true, _) => image::reconstruct(&lines, false),
            };
            let (px, w, h) = if feed { image::window_for_feed(&px, w, h) } else { (px, w, h) };
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} ({}x{})", out.display(), w, h);
        }
        Command::DecodeLines { input, out, crop } => {
            let raw = std::fs::read(&input)?;
            let lines = image::load_lines_raw(&raw);
            println!("[i] loaded {} lines x {} cols", lines.rows, lines.cols);
            if lines.rows < 20 {
                bail!("too few lines ({})", lines.rows);
            }
            let (px, w, h) = image::reconstruct(&lines, crop);
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} ({}x{})", out.display(), w, h);
        }
        Command::Feed { image: img, socket } => {
            let sock = resolve_socket(socket)?;
            let (px, w, h) = read_pgm(&img)?;
            virtimage::send_image(&sock, &px, w, h)?;
            println!("[+] fed {}x{} image to {sock}", w, h);
        }
        Command::Run { socket } => {
            let sock = resolve_socket(socket)?;
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            let stream = capture::arm_capture(&mut dev, &mut rec, &cfg);
            session::close(&dev, &mut rec);
            let stream = stream?;
            let cfg = image::DliConfig::load_main(&cfg.data_dir)?;
            let lines = image::decode_ep2(&stream, 272, &cfg);
            // Never feed a blank capture (a missed swipe) into an enrollment.
            let (accept, contact) = finger_gate(&lines, DEFAULT_MIN_CONTACT);
            if !accept {
                bail!("no finger detected ({contact} contact rows < {DEFAULT_MIN_CONTACT}) — nothing fed");
            }
            let Some((px, w, h)) = swipe::reconstruct_swipe(&lines, device.lateral()) else {
                bail!("finger touched but did not swipe ({contact} contact rows, no motion) — nothing fed");
            };
            let (fpx, fw, fh) = image::window_for_feed(&px, w, h);
            // VFS_SAVE_FED=<dir>: keep every fed image + its decrypted stream (offline analysis).
            if let Ok(dir) = std::env::var("VFS_SAVE_FED") {
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
                image::write_pgm(&format!("{dir}/fed_{ts}.pgm"), &fpx, fw, fh)?;
                std::fs::write(format!("{dir}/fed_{ts}.stream"), &stream)?;
            }
            virtimage::send_image(&sock, &fpx, fw as u32, fh as u32)?;
            println!("[+] captured a {w}x{h} swipe ({contact} contact rows) and fed {fw}x{fh} to virtual_image");
        }
        Command::WindowTest { count, dump } => {
            if let Some(d) = &dump {
                std::fs::create_dir_all(d)?;
            }
            let mut dev = usb::Sensor::open(device)?;
            let mut rec = session::open_session(&mut dev, &cfg)?;
            let dli = image::DliConfig::load_main(&cfg.data_dir)?;
            let tested = (|| -> Result<()> {
                let mut cap = capture::Capture::new(&mut dev, &mut rec, &cfg)?;
                let t0 = std::time::Instant::now();
                cap.prepare()?;
                println!("[i] prepared in {:.1}s", t0.elapsed().as_secs_f32());
                for n in 0..count {
                    let t = std::time::Instant::now();
                    let stream = cap.window()?;
                    if let Some(d) = &dump {
                        std::fs::write(d.join(format!("win{n:02}.stream")), &stream)?;
                    }
                    let lines = image::decode_ep2(&stream, 272, &dli);
                    let swipe = swipe::reconstruct_swipe(&lines, device.lateral()).map(|(_, w, h)| format!("{w}x{h}"));
                    println!(
                        "[i] window {n}: {:.1}s, {} bytes, {} lines, {} contact rows, median line sd {:.1}, swipe {:?}",
                        t.elapsed().as_secs_f32(),
                        stream.len(),
                        lines.rows,
                        lines.contact_rows(image::CONTACT_SD),
                        lines.median_line_std(),
                        swipe
                    );
                }
                cap.finish()?;
                println!("[+] finished after {:.1}s", t0.elapsed().as_secs_f32());
                Ok(())
            })();
            session::close(&dev, &mut rec);
            tested?;
        }
        Command::Daemon { socket, min_contact, once, gap, fprintd } => {
            let sock = resolve_socket(socket)?;
            run_daemon(device, &cfg, &sock, min_contact, once, gap, fprintd)?;
        }
    }
    Ok(())
}

/// Default `--min-contact`: well above a blank sensor (0) and far below a swipe
/// (~4000-6000 rows), so partial swipes still pass.
const DEFAULT_MIN_CONTACT: usize = 300;

/// The finger gate: enough decoded lines and at least `min_contact` rows with
/// real finger contact (see `Lines::contact_sd`). Returns (accept, contact rows).
fn finger_gate(lines: &image::Lines, min_contact: usize) -> (bool, usize) {
    let contact = lines.contact_rows(image::CONTACT_SD);
    (lines.rows >= 60 && contact >= min_contact, contact)
}

/// Decide whether one imaging window holds a usable swipe and, if so, turn it
/// into the image to feed libfprint. Gate on finger contact rows: with the fixed
/// column pattern removed, a blank sensor is quiet (row sd ~4) and a swiped
/// finger's rows are ~25-60. (The old ridge_peak gate measured noise statistics,
/// not ridges — NOTES 2026-10-01.)
fn swipe_from_window(stream: &[u8], dli: &image::DliConfig, min_contact: usize, lateral: Lateral) -> Option<(Vec<u8>, u32, u32)> {
    let lines = image::decode_ep2(stream, 272, dli);
    let (accept, contact) = finger_gate(&lines, min_contact);
    if !accept {
        log::debug!("no finger in this window ({contact} contact rows < {min_contact})");
        return None;
    }
    let Some((px, w, h)) = swipe::reconstruct_swipe(&lines, lateral) else {
        log::info!("finger touched but did not swipe ({contact} contact rows, no motion)");
        return None;
    };
    // Enlarge and clamp the pixels we actually feed to a libfprint-acceptable height.
    let (fpx, fw, fh) = image::window_for_feed(&px, w, h);
    log::info!("finger captured: {w}x{h} ({contact} contact rows); feeding {fw}x{fh}");
    Some((fpx, fw as u32, fh as u32))
}

/// (Re)establish a live session: recover the device (waiting out any USB
/// re-enumeration, falling back to a fresh open) and run the SSL handshake.
fn reestablish(dev: &mut usb::Sensor, cfg: &session::Config) -> Result<crypto::Record> {
    if dev.reopen().is_err() {
        // The handle could not be recovered in place (e.g. the device fully went
        // away); open the same model from scratch.
        let device = dev.device;
        *dev = usb::Sensor::open(device)?;
    }
    session::open_session(dev, cfg)
}

/// Imaging windows opened for one request before recalibrating (~4 s each).
const MAX_WINDOWS_PER_REQUEST: usize = 30;
/// After feeding a swipe, how long to wait for the next scan of the same
/// request (the next enroll stage, or a retry) before closing the capture.
const NEXT_SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Serve one fingerprint request: calibrate once, then open imaging windows back
/// to back, feeding each swipe as soon as its window closes, until nothing is
/// waiting for a finger any more. Returns the number of swipes fed.
#[allow(clippy::too_many_arguments)]
fn serve_request(
    cap: &mut capture::Capture,
    mut listener: std::os::unix::net::UnixStream,
    sock: &str,
    dli: &image::DliConfig,
    min_contact: usize,
    lateral: Lateral,
    fprintd: bool,
    once: bool,
) -> Result<usize> {
    let mut fed = 0;
    for _ in 0..MAX_WINDOWS_PER_REQUEST {
        if !virtimage::still_wanted(&listener, fprintd) {
            break;
        }
        let stream = cap.window()?;
        let Some((px, w, h)) = swipe_from_window(&stream, dli, min_contact, lateral) else { continue };
        match virtimage::send_on(&mut listener, &px, w, h) {
            Ok(()) => fed += 1,
            Err(e) => log::warn!("captured {w}x{h} but the request was gone: {e}"),
        }
        if once {
            break;
        }
        // One image per connection: reconnect for the next scan, if one follows.
        match virtimage::wait_for_request(sock, fprintd, Some(NEXT_SCAN_WAIT)) {
            Some(next) => listener = next,
            None => break,
        }
    }
    Ok(fed)
}

/// Feeder loop: when a fingerprint is requested, capture swipes and push them to
/// libfprint's virtual_image socket. The device is opened and the SSL session
/// established ONCE and reused across captures (per-capture open/handshake churn
/// was re-enumerating the sensor). A capture error rebuilds the session and
/// continues, so the daemon survives a re-enumeration or an fprintd restart.
fn run_daemon(
    device: &'static Device,
    cfg: &session::Config,
    sock: &str,
    min_contact: usize,
    once: bool,
    gap: u64,
    fprintd: bool,
) -> Result<()> {
    // No terminal cues; the swipe cue is the LED (VFS_CUE_LED).
    std::env::set_var("VFS_NO_PROMPT", "1");
    let dli = image::DliConfig::load_main(&cfg.data_dir)?;
    let lateral = device.lateral();
    log::info!("vfs495 feeder daemon: socket {sock}, min_contact {min_contact}");
    log::info!("idle until a fingerprint is requested (enroll/verify), then capturing");

    // Catch stop/termination to close the SSL session cleanly before exit: a kill
    // otherwise leaves the session half-open and wedges the sensor (2604).
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone());
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone());

    let mut dev = loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        match usb::Sensor::open(device) {
            Ok(d) => break d,
            Err(e) => {
                log::warn!("sensor not available: {e}; retrying in 10s");
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
    };
    // Retry the startup handshake instead of exiting: at boot the sensor may not be
    // ready, and after a prior session it can briefly return 2604/Pipe until it
    // settles. Stay up and retry gently rather than crash-looping through systemd.
    let mut rec = loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        match session::open_session(&mut dev, cfg) {
            Ok(r) => break r,
            Err(e) => {
                log::warn!("startup handshake failed: {e}; retrying in 30s");
                std::thread::sleep(std::time::Duration::from_secs(30));
                let _ = dev.reopen();
            }
        }
    };
    loop {
        let result: Result<()> = (|| -> Result<()> {
            let mut cap = capture::Capture::new(&mut dev, &mut rec, cfg)?;
            cap.prepare()?;
            log::info!("prepared; warm session ready, waiting for fingerprint requests");
            loop {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok(());
                }
                let Some(listener) = virtimage::wait_for_request(
                    sock,
                    fprintd,
                    Some(std::time::Duration::from_secs(1)),
                ) else {
                    continue;
                };
                log::info!("fingerprint requested; recording swipe");
                let fed =
                    serve_request(&mut cap, listener, sock, &dli, min_contact, lateral, fprintd, once)?;
                log::info!("request served: {fed} swipe(s) fed");
                if once {
                    return Ok(());
                }
                if gap > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(gap));
                }
            }
        })();
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            log::info!("shutdown: sending close_notify to end the session cleanly");
            session::close(&dev, &mut rec);
            return Ok(());
        }
        match result {
            Ok(()) => break,
            Err(e) => {
                log::warn!("capture failed: {e}; rebuilding session");
                std::thread::sleep(std::time::Duration::from_secs(gap.max(3)));
                match reestablish(&mut dev, cfg) {
                    Ok(new_rec) => {
                        rec = new_rec;
                        log::info!("session re-established");
                    }
                    Err(e2) => log::warn!("session rebuild failed: {e2}; will retry"),
                }
            }
        }
    }
    Ok(())
}

fn resolve_socket(opt: Option<String>) -> Result<String> {
    match opt.or_else(|| std::env::var("FP_VIRTUAL_IMAGE").ok()) {
        Some(s) => Ok(s),
        None => bail!("no socket: pass --socket or set FP_VIRTUAL_IMAGE"),
    }
}

fn read_pgm(path: &PathBuf) -> Result<(Vec<u8>, u32, u32)> {
    let raw = std::fs::read(path)?;
    // parse a minimal P5 header
    let mut pos = 0usize;
    let mut tokens = Vec::new();
    while tokens.len() < 4 && pos < raw.len() {
        while pos < raw.len() && (raw[pos] as char).is_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < raw.len() && !(raw[pos] as char).is_whitespace() {
            pos += 1;
        }
        tokens.push(String::from_utf8_lossy(&raw[start..pos]).to_string());
    }
    if tokens.len() < 4 || tokens[0] != "P5" {
        bail!("not a P5 PGM");
    }
    let w: u32 = tokens[1].parse()?;
    let h: u32 = tokens[2].parse()?;
    pos += 1; // single whitespace after maxval
    let need = (w * h) as usize;
    if pos + need > raw.len() {
        bail!("PGM truncated");
    }
    Ok((raw[pos..pos + need].to_vec(), w, h))
}
