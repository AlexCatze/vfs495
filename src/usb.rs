//! USB transport for the VFS495 over libusb (`rusb`).
//!
//! Interface 0, vendor-specific. Endpoints (confirmed by descriptor dump):
//!   * EP1 OUT  (0x01) bulk 64  — command channel
//!   * EP1 IN   (0x81) bulk 64  — command replies
//!   * EP2 IN   (0x82) bulk 64  — plaintext image stream
//!
//! Only reads and replays of byte sequences already observed from HP's binary
//! are performed here. No command is synthesised or fuzzed.

use anyhow::{anyhow, Context, Result};
use rusb::{Device as UsbDevice, DeviceHandle, GlobalContext};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Optional wire log (set `$VFS_WIRE` to a path) for diffing against HP traces.
fn wire_log(tag: &str, ep: u8, data: &[u8]) {
    static LOG: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    let slot = LOG.get_or_init(|| {
        std::env::var("VFS_WIRE")
            .ok()
            .and_then(|p| std::fs::File::create(p).ok())
            .map(Mutex::new)
    });
    if let Some(m) = slot {
        if let Ok(mut f) = m.lock() {
            let head: String = data.iter().take(16).map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(f, "{tag} ep=0x{:02x} len={} {head}", ep, data.len());
        }
    }
}

use crate::device::Device;

pub const VID: u16 = 0x138a;
pub const EP_OUT: u8 = 0x01;
pub const EP_IN: u8 = 0x81;
pub const EP_IMG: u8 = 0x82;

/// The profile of the first supported sensor on the bus, if any.
pub fn detect() -> Option<&'static Device> {
    for dev in rusb::devices().ok()?.iter() {
        if let Ok(desc) = dev.device_descriptor() {
            if desc.vendor_id() == VID {
                if let Some(d) = Device::by_pid(desc.product_id()) {
                    return Some(d);
                }
            }
        }
    }
    None
}

/// An open, claimed handle to the sensor.
pub struct Sensor {
    handle: DeviceHandle<GlobalContext>,
    reattach: bool,
    /// The profile of the sensor this handle is on.
    pub device: &'static Device,
    /// (bus, address) of the device this handle is on. A re-enumeration always
    /// gives the sensor a new address, so this tells a real reboot apart from a
    /// transfer error on a device that is still there.
    location: (u8, u8),
}

impl Sensor {
    /// Find, open and claim interface 0 of the given sensor model on the bus.
    pub fn open(device: &'static Device) -> Result<Self> {
        let dev = find_device(device.pid)
            .with_context(|| format!("{} (138a:{:04x}) not found on USB", device.model, device.pid))?;
        let handle = dev.open().context("failed to open device (permissions? try sudo / udev rule)")?;

        let mut reattach = false;
        if handle.kernel_driver_active(0).unwrap_or(false) {
            handle
                .detach_kernel_driver(0)
                .context("failed to detach kernel driver")?;
            reattach = true;
        }
        handle.set_active_configuration(1).ok();
        handle.claim_interface(0).context("failed to claim interface 0")?;
        Ok(Sensor { handle, reattach, device, location: (dev.bus_number(), dev.address()) })
    }

    /// Whether the device behind this handle has left the bus (rebooted),
    /// waiting up to `wait_ms` for it to go: right after a failed transfer the
    /// pre-reboot device is often still enumerated for a moment.
    pub fn left_bus(&self, wait_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(wait_ms);
        loop {
            if !device_at(self.location) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// USB port reset (HP's `palSensorHWReset` does exactly this), then
    /// re-acquire the device: the sensor comes back as if freshly plugged in.
    pub fn usb_reset(&mut self) -> Result<()> {
        // On success the handle stays valid (libusb restores the claimed
        // interface); if the device re-enumerated instead, re-acquire it.
        match self.handle.reset() {
            Ok(()) => {
                std::thread::sleep(Duration::from_millis(300));
                Ok(())
            }
            Err(_) => self.reopen(),
        }
    }

    /// Clear a stall on EP1 OUT after a failed write on a device that did not
    /// reboot.
    pub fn clear_halt_out(&self) {
        let _ = self.handle.clear_halt(EP_OUT);
    }

    /// Write a command to EP1 OUT.
    pub fn write(&self, data: &[u8], timeout_ms: u64) -> Result<usize> {
        wire_log("W", EP_OUT, data);
        self.handle
            .write_bulk(EP_OUT, data, Duration::from_millis(timeout_ms))
            .map_err(|e| anyhow!("EP_OUT write failed: {e}"))
    }

    /// Read a reply from EP1 IN.
    pub fn read(&self, max: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let n = self
            .handle
            .read_bulk(EP_IN, &mut buf, Duration::from_millis(timeout_ms))
            .map_err(|e| anyhow!("EP_IN read failed: {e}"))?;
        buf.truncate(n);
        wire_log("R", EP_IN, &buf);
        Ok(buf)
    }

    /// Read one complete SSLv3 record from EP1 IN.
    ///
    /// In-session replies are `<type> 03 00 <len16-be> <ciphertext>` records that
    /// can span several 64-byte bulk packets, so a single `read_bulk` may return
    /// only the header or a partial body. This accumulates bulk transfers until the
    /// full record (5-byte header + `len` body bytes) is present, then returns it.
    /// The poll loop must consume every inbound record in order to keep the CBC IV
    /// chain (`siv`) and receive sequence aligned.
    pub fn read_record(&self, timeout_ms: u64) -> Result<Vec<u8>> {
        self.read_record_split(timeout_ms, timeout_ms)
    }

    /// Like `read_record`, but with two timeouts: `first_ms` bounds the wait for the
    /// *first* byte of a record, and `rest_ms` bounds the wait for the remainder once
    /// any byte has arrived. A timeout before the first byte returns `Err` with
    /// nothing consumed, so a caller may poll EP1 with a short `first_ms` while
    /// interleaving other work (draining EP2) without ever losing a partial record.
    pub fn read_record_split(&self, first_ms: u64, rest_ms: u64) -> Result<Vec<u8>> {
        let mut deadline = std::time::Instant::now() + Duration::from_millis(first_ms);
        let mut acc: Vec<u8> = Vec::with_capacity(4096);
        let mut chunk = vec![0u8; 4096];
        loop {
            // Header first: need 5 bytes to know the record length.
            let need = if acc.len() < 5 {
                5
            } else {
                let ln = u16::from_be_bytes([acc[3], acc[4]]) as usize;
                5 + ln
            };
            if acc.len() >= need && acc.len() >= 5 {
                let ln = u16::from_be_bytes([acc[3], acc[4]]) as usize;
                if acc.len() >= 5 + ln {
                    let rec = acc[..5 + ln].to_vec();
                    wire_log("R", EP_IN, &rec);
                    return Ok(rec);
                }
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("EP_IN record read timed out (have {} bytes)", acc.len());
            }
            match self.handle.read_bulk(EP_IN, &mut chunk, remaining) {
                Ok(n) => {
                    if acc.is_empty() && n > 0 {
                        // First byte seen: switch to the (longer) continuation budget.
                        deadline = std::time::Instant::now() + Duration::from_millis(rest_ms);
                    }
                    acc.extend_from_slice(&chunk[..n]);
                }
                Err(rusb::Error::Timeout) => {
                    anyhow::bail!("EP_IN record read timed out (have {} bytes)", acc.len())
                }
                Err(e) => return Err(anyhow!("EP_IN read failed: {e}")),
            }
        }
    }

    /// Read a chunk of the image stream from EP2 IN. Returns an empty Vec on timeout.
    pub fn read_image(&self, max: usize, timeout_ms: u64) -> Vec<u8> {
        let mut buf = vec![0u8; max];
        match self
            .handle
            .read_bulk(EP_IMG, &mut buf, Duration::from_millis(timeout_ms))
        {
            Ok(n) => {
                buf.truncate(n);
                wire_log("R", EP_IMG, &buf);
                buf
            }
            Err(_) => Vec::new(),
        }
    }

    /// Drain any queued image data (used after the reset-image init command).
    pub fn drain_image(&self) {
        loop {
            let chunk = self.read_image(16384, 400);
            if chunk.len() < 16384 {
                break;
            }
        }
    }

    /// Convenience: write then read one reply.
    pub fn cmd(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.write(data, 3000)?;
        self.read(0x400, 3000)
    }

    /// Re-acquire the device after it re-enumerates (the capture flow issues
    /// `0x04` soft resets). The firmware keeps the SSL session across the reset,
    /// so callers keep their existing `Record`; only the USB handle changes.
    /// Retries for up to ~3s while the device comes back on the bus.
    pub fn reopen(&mut self) -> Result<()> {
        // drop the stale handle first
        let _ = self.handle.release_interface(0);
        // Wait for the OLD device to drop off the bus before grabbing a handle:
        // right after a Pipe error the pre-reboot device is often still enumerated,
        // and opening it leads to a doomed handshake + a wasted second reopen. A
        // confirmed disconnect (keyed on the old bus address) makes the next find
        // return the FRESH device; a sensor already back under its new address is
        // not waited on.
        self.left_bus(2000);
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(dev) = find_device(self.device.pid) {
                if let Ok(handle) = dev.open() {
                    self.reattach = false;
                    if handle.kernel_driver_active(0).unwrap_or(false) {
                        let _ = handle.detach_kernel_driver(0);
                        self.reattach = true;
                    }
                    // NB: do NOT re-issue set_active_configuration(1) here. libusb
                    // treats a repeated SET_CONFIGURATION as a lightweight device
                    // reset (endpoints/toggles, and the firmware SSL session); HP
                    // never does it across the imaging re-enumeration, so neither do
                    // we — just re-claim the interface.
                    if handle.claim_interface(0).is_ok() {
                        self.handle = handle;
                        self.location = (dev.bus_number(), dev.address());
                        // The device re-enumerates (findable on USB) well before its
                        // firmware is ready to resume the SSL session; resuming too
                        // early reads 5-byte zeros, so wait for it to settle.
                        std::thread::sleep(Duration::from_millis(self.device.settle_ms()));
                        return Ok(());
                    }
                }
            }
        }
        anyhow::bail!("device did not re-enumerate within timeout after reset")
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(0);
        if self.reattach {
            let _ = self.handle.attach_kernel_driver(0);
        }
    }
}

/// Whether this sensor is still enumerated at `(bus, address)`.
fn device_at((bus, addr): (u8, u8)) -> bool {
    rusb::devices()
        .ok()
        .map(|list| {
            list.iter()
                .any(|d| d.bus_number() == bus && d.address() == addr)
        })
        .unwrap_or(false)
}

/// The first `138a:<pid>` device on the bus.
fn find_device(pid: u16) -> Option<UsbDevice<GlobalContext>> {
    rusb::devices().ok()?.iter().find(|d| {
        d.device_descriptor()
            .map(|desc| desc.vendor_id() == VID && desc.product_id() == pid)
            .unwrap_or(false)
    })
}
