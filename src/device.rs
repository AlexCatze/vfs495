//! Per-sensor profiles for the Validity "Falcon" family.
//!
//! The VFS495 and VFS471 share the transport, the SSLv3 crypto and the EP2 image
//! format, but differ in device ID, whether the handshake needs a client
//! certificate, the in-session command sequence (and so the indices of its
//! imaging windows), how calibration is obtained, and how imaging is gated. One
//! [`Device`] captures all of that so the rest of the driver stays model-agnostic;
//! the right profile is chosen by the USB product ID actually on the bus.

/// Source of the per-session AFE calibration values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Calib {
    /// Compute them from this session's sweep frames (ports of HP's steps).
    Compute,
    /// Replay the values recorded in `capture_seq.json` (the sensor's own, when
    /// the per-step algorithms do not fit this model's sweep frames).
    Replay,
}

/// Lateral-drift handling in swipe reconstruction (see `swipe.rs`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lateral {
    /// No lateral shift. A straight swipe has ~zero real drift, and integrating a
    /// biased estimate shears the print (VFS471, confirmed on hardware).
    None,
    /// Remove only the DC bias of the drift estimate.
    Detrend,
    /// Accumulate the full per-line drift (the original VFS495 behavior).
    Full,
}

/// Everything that varies between sensors in the family.
pub struct Device {
    /// Short model name; also the `data/<model>/` runtime-data directory.
    pub model: &'static str,
    /// USB product ID under vendor `0x138a`.
    pub pid: u16,
    /// Whether the secure handshake must send a client Certificate +
    /// CertificateVerify (VFS471) or a plain RSA ClientKeyExchange (VFS495).
    pub needs_client_cert: bool,
    /// Where the per-session calibration values come from.
    pub calib: Calib,
    /// Default lateral-drift handling (overridable with `VFS_LATERAL`).
    pub lateral: Lateral,
    /// Whether the sensor gates imaging on its own finger detection: after the
    /// imaging command, nothing streams until a finger is present and the driver
    /// must poll GetFingerState (`0x17`). VFS495 streams unconditionally.
    pub finger_gated: bool,
    /// `capture_seq` indices: setup/calibration run before the first window.
    pub prepare: std::ops::Range<usize>,
    /// One repeatable imaging window (poll, imaging command, close).
    pub window_unit: std::ops::RangeInclusive<usize>,
    /// Indices of the imaging commands whose window a finger must swipe through.
    pub swipe_windows: [usize; 2],
    /// Trailing commands sent when a capture is finished.
    pub finish: std::ops::Range<usize>,
    /// Firmware-settle wait after a re-enumeration, in ms (overridable with
    /// `VFS_SETTLE_MS`).
    pub settle_ms: u64,
}

/// VFS471 (`138a:003c`). Client-cert handshake; 28-command sequence; replayed
/// calibration; sensor-gated imaging; lateral shift off (shear fix).
pub const VFS471: Device = Device {
    model: "vfs471",
    pid: 0x003c,
    needs_client_cert: true,
    calib: Calib::Replay,
    lateral: Lateral::None,
    finger_gated: true,
    prepare: 0..24,
    window_unit: 24..=27,
    swipe_windows: [22, 26],
    finish: 28..28,
    settle_ms: 300,
};

/// VFS495 (`138a:003f`). The original target: plain-RSA handshake; 42-command
/// sequence; per-session computed calibration; free-running imaging.
pub const VFS495: Device = Device {
    model: "vfs495",
    pid: 0x003f,
    needs_client_cert: false,
    calib: Calib::Compute,
    lateral: Lateral::Full,
    finger_gated: false,
    prepare: 0..22,
    window_unit: 26..=29,
    swipe_windows: [23, 27],
    finish: 30..42,
    settle_ms: 1500,
};

/// Every supported sensor.
pub const ALL: &[&Device] = &[&VFS471, &VFS495];

impl Device {
    /// The calibration mode, letting `VFS_NO_CALIB` force replay for diagnostics.
    pub fn calib(&self) -> Calib {
        if std::env::var("VFS_NO_CALIB").is_ok() {
            Calib::Replay
        } else {
            self.calib
        }
    }

    /// The lateral-drift mode, overridable with `VFS_LATERAL=none|detrend|full`.
    pub fn lateral(&self) -> Lateral {
        match std::env::var("VFS_LATERAL").as_deref() {
            Ok("none") => Lateral::None,
            Ok("detrend") => Lateral::Detrend,
            Ok("full") => Lateral::Full,
            _ => self.lateral,
        }
    }

    /// Firmware-settle wait after a re-enumeration, `VFS_SETTLE_MS` overriding it.
    pub fn settle_ms(&self) -> u64 {
        std::env::var("VFS_SETTLE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.settle_ms)
    }

    /// Look up a profile by model name (`vfs471`, `vfs495`).
    pub fn by_name(name: &str) -> Option<&'static Device> {
        ALL.iter().copied().find(|d| d.model == name)
    }

    /// Look up a profile by USB product ID.
    pub fn by_pid(pid: u16) -> Option<&'static Device> {
        ALL.iter().copied().find(|d| d.pid == pid)
    }
}
