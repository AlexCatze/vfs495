//! Open decode of VFS495 image data.
//!
//! Two stages, mirroring HP's `irDliRTFalconData` / `UnpackLineRT`:
//!
//!   1. **Unpack** ([`unpack_line`]) — turn one packed scan line into a
//!      descrambled row of 8-bit pixels. This is a clean-room reimplementation
//!      of `UnpackLineRT` (three modes; see below), driven by an open
//!      [`DliConfig`] rather than HP's opaque config blob.
//!   2. **Assemble + reconstruct** ([`load_lines_raw`] / [`reconstruct`]) — stack
//!      the descrambled rows into an image, remove the fixed column pattern,
//!      apply local-contrast normalization, optionally crop to the swipe.
//!
//! ### UnpackLineRT modes (from the binary at 0x46f510)
//!   * **mode 8** — one source byte per pixel: `dst[perm[i]] = src[i]`.
//!   * **mode 4** — two pixels per byte: low nibble `<<4` → `perm[i]`, high nibble
//!     (kept in place) → `perm[i+1]`.
//!   * **general** — variable-bit samples: sample `i` uses `bits[i]` bits (clamped
//!     to `max_bits`), read little-endian from the packed stream, left-justified
//!     to 8 bits (`<< (8 - w)`), then scattered via `perm[i]`.
//!
//! The permutation table is `data/<model>/perm.bin` (HP keeps it at
//! `cfg+0x57c`). The per-column `bits` table (HP: `cfg+8`) is capture-specific;
//! dump it once with `scripts/dump_dli_config.gdb.py` for the raw-EP2 path.

use anyhow::{Context, Result};
use std::path::Path;

/// Open equivalent of HP's DLI unpack config blob.
#[derive(Clone)]
pub struct DliConfig {
    /// 4, 8, or any other value → the general variable-bit path.
    pub mode: u32,
    /// Number of output pixels per line.
    pub width: usize,
    /// Max bits per sample (general path clamp; HP: low nibble of the width byte).
    pub max_bits: u32,
    /// Per-column bit widths (general path only).
    pub bits: Vec<u8>,
    /// Column descramble: output index for source column `i`.
    pub perm: Vec<i16>,
}

impl DliConfig {
    /// Main-image config: perm from `data/<model>/perm.bin`.
    /// `mode`/`bits` default to a plain 8-bit scatter and may be overridden by
    /// `data/<model>/dli_config.json` when present (see `dump_dli_config.gdb.py`).
    pub fn load_main(data_dir: &Path) -> Result<Self> {
        let perm = load_perm(&data_dir.join("perm.bin"))?;
        let width = perm.len();
        let cfg_path = data_dir.join("dli_config.json");
        if cfg_path.exists() {
            let raw = std::fs::read_to_string(&cfg_path)?;
            let j: serde_json::Value = serde_json::from_str(&raw)?;
            let mode = j["mode"].as_u64().unwrap_or(8) as u32;
            let max_bits = j["max_bits"].as_u64().unwrap_or(8) as u32;
            // a dumped config carries its own perm + width; fall back to perm.bin
            let perm = j["perm"]
                .as_array()
                .map(|a| a.iter().map(|v| v.as_i64().unwrap_or(0) as i16).collect())
                .unwrap_or(perm);
            let width = j["width"].as_u64().map(|w| w as usize).unwrap_or(perm.len());
            let bits = j["bits"]
                .as_array()
                .map(|a| a.iter().map(|v| v.as_u64().unwrap_or(8) as u8).collect())
                .unwrap_or_else(|| vec![8u8; width]);
            Ok(DliConfig { mode, width, max_bits, bits, perm })
        } else {
            Ok(DliConfig { mode: 8, width, max_bits: 8, bits: vec![8; width], perm })
        }
    }
}

fn load_perm(path: &Path) -> Result<Vec<i16>> {
    let raw = std::fs::read(path).with_context(|| format!("reading perm table {}", path.display()))?;
    Ok(raw
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// Reimplementation of `UnpackLineRT`: unpack one packed line's pixel payload
/// (i.e. the bytes *after* the 8-byte frame header) into `width` descrambled
/// 8-bit pixels. Faithful to the three branches of HP's routine.
pub fn unpack_line(payload: &[u8], cfg: &DliConfig) -> Vec<u8> {
    let width = cfg.width;
    let mut out = vec![0u8; width];
    let put = |out: &mut [u8], i: usize, val: u8| {
        let p = cfg.perm[i] as usize;
        if p < out.len() {
            out[p] = val;
        }
    };

    match cfg.mode {
        8 => {
            for i in 0..width.min(payload.len()) {
                put(&mut out, i, payload[i]);
            }
        }
        4 => {
            let mut i = 0usize;
            let mut src = 0usize;
            while i + 1 < width && src < payload.len() {
                let byte = payload[src];
                src += 1;
                put(&mut out, i, (byte & 0x0f) << 4);
                put(&mut out, i + 1, byte & 0xf0);
                i += 2;
            }
        }
        _ => {
            // general variable-bit path
            let mut byte_idx = 0usize;
            let mut bitoff = 0u32;
            for i in 0..width {
                let mut w = cfg.bits.get(i).copied().unwrap_or(8) as u32;
                if w > cfg.max_bits {
                    w = cfg.max_bits;
                }
                if w == 0 || w > 8 {
                    continue;
                }
                let b0 = payload.get(byte_idx).copied().unwrap_or(0) as u32;
                let b1 = payload.get(byte_idx + 1).copied().unwrap_or(0) as u32;
                let mask = (1u32 << w) - 1;
                let sample = ((b1 << 8 | b0) >> bitoff) & mask;
                put(&mut out, i, (sample << (8 - w)) as u8);
                let nb = bitoff + w;
                if nb > 7 {
                    byte_idx += 1;
                    bitoff = nb - 8;
                } else {
                    bitoff = nb;
                }
            }
        }
    }
    out
}

/// A decoded, unreconstructed line matrix (row-major, `f32` intensities).
pub struct Lines {
    pub data: Vec<f32>,
    pub rows: usize,
    pub cols: usize,
}

impl Lines {
    /// Median per-line standard deviation — a finger-contact quality metric.
    ///
    /// A ridged fingerprint line swings between ridge and valley, giving a high
    /// per-row std (~70 on this sensor); a flat no-contact/baseline line is
    /// near-uniform (std well under 25). Taking the median over all rows rejects
    /// a few stray high-contrast rows in an otherwise blank capture.
    pub fn median_line_std(&self) -> f32 {
        if self.rows == 0 || self.cols == 0 {
            return 0.0;
        }
        let mut sds: Vec<f32> = (0..self.rows)
            .map(|r| {
                let row = &self.data[r * self.cols..(r + 1) * self.cols];
                let mean = row.iter().sum::<f32>() / self.cols as f32;
                let var = row.iter().map(|&x| (x - mean) * (x - mean)).sum::<f32>() / self.cols as f32;
                var.sqrt()
            })
            .collect();
        sds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        sds[sds.len() / 2]
    }

    /// Per-row contact strength: the std of each row after subtracting the
    /// sensor's fixed column pattern, over the main sensing columns.
    ///
    /// The raw per-row std is dominated by the fixed column pattern (~48 with or
    /// without a finger), which is why contrast looked useless as a finger
    /// signal. With the pattern removed, a blank sensor is ~4–10 while a swiped
    /// finger's rows are ~45–60 (HP's recorded swipe; NOTES.md 2026-10-01). The
    /// pattern is estimated as the per-column MEDIAN over the capture, which is
    /// the background as long as a finger covers under half of the rows — true
    /// for a swipe, not for a finger held still for the whole capture.
    pub fn contact_sd(&self) -> Vec<f32> {
        self.contact_rows_bg().1
    }

    /// Rows of the main sensing columns with the fixed column pattern (per-column
    /// median) removed, plus each row's std.
    fn contact_rows_bg(&self) -> (Vec<Vec<f32>>, Vec<f32>) {
        let cols = self.cols.min(CONTACT_COLS);
        if self.rows == 0 || cols == 0 {
            return (Vec::new(), Vec::new());
        }
        let bg: Vec<f32> = (0..cols)
            .map(|x| {
                let mut col: Vec<f32> = (0..self.rows).map(|y| self.data[y * self.cols + x]).collect();
                col.sort_by(|a, b| a.partial_cmp(b).unwrap());
                col[col.len() / 2]
            })
            .collect();
        let rows: Vec<Vec<f32>> = (0..self.rows)
            .map(|y| {
                let row = &self.data[y * self.cols..y * self.cols + cols];
                row.iter().zip(&bg).map(|(v, b)| v - b).collect()
            })
            .collect();
        let sd = rows
            .iter()
            .map(|d| {
                let mean = d.iter().sum::<f32>() / cols as f32;
                (d.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / cols as f32).sqrt()
            })
            .collect();
        (rows, sd)
    }

    /// Number of rows whose [`contact_sd`](Self::contact_sd) reaches `min_sd`.
    pub fn contact_rows(&self, min_sd: f32) -> usize {
        self.contact_sd().iter().filter(|&&s| s >= min_sd).count()
    }
}

/// Main sensing columns (the right-hand columns carry fixed calibration bars).
const CONTACT_COLS: usize = 200;
/// Row std (fixed pattern removed) that counts as finger contact: a blank
/// sensor is ~4-10, a finger's rows ~25-60.
pub const CONTACT_SD: f32 = 25.0;
/// Parse a `lines.raw`-format buffer: repeated `<u16 LE width><width bytes>`
/// (the descrambled output of [`unpack_line`] / HP's UnpackLineRT).
pub fn load_lines_raw(buf: &[u8]) -> Lines {
    let mut data = Vec::new();
    let mut rows = 0usize;
    let mut cols = 0usize;
    let mut off = 0usize;
    while off + 2 <= buf.len() {
        let w = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if w == 0 || off + w > buf.len() {
            break;
        }
        if cols == 0 {
            cols = w;
        }
        if w == cols {
            data.extend(buf[off..off + w].iter().map(|&b| b as f32));
            rows += 1;
        }
        off += w;
    }
    Lines { data, rows, cols }
}

/// Extract the longest run of fixed-stride EP2 frames and unpack each with `cfg`.
/// (For the raw-EP2 path; needs a correct [`DliConfig`] for the frame type.)
pub fn decode_ep2(buf: &[u8], stride: usize, cfg: &DliConfig) -> Lines {
    let mut marks = Vec::new();
    let mut i = 0usize;
    while i + 1 < buf.len() {
        if buf[i] == 0x01 && buf[i + 1] == 0xfe {
            marks.push(i);
        }
        i += 1;
    }
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut k = 0usize;
    while k < marks.len() {
        let mut j = k;
        while j + 1 < marks.len() && marks[j + 1] - marks[j] == stride {
            j += 1;
        }
        if j - k + 1 > best_len {
            best_len = j - k + 1;
            best_start = k;
        }
        k = j + 1;
    }
    let mut data = Vec::new();
    let mut rows = 0usize;
    for idx in best_start..best_start + best_len {
        let body = marks[idx] + 8; // skip 8-byte header
        if body <= buf.len() {
            let line = unpack_line(&buf[body..], cfg);
            data.extend(line.iter().map(|&b| b as f32));
            rows += 1;
        }
    }
    Lines { data, rows, cols: cfg.width }
}

// ---- reconstruction -------------------------------------------------------

/// Separable box blur (radius `r`).
pub(crate) fn box_blur(src: &[f32], rows: usize, cols: usize, r: usize) -> Vec<f32> {
    let mut tmp = vec![0f32; src.len()];
    for y in 0..rows {
        for x in 0..cols {
            let x0 = x.saturating_sub(r);
            let x1 = (x + r + 1).min(cols);
            let mut s = 0f32;
            for xx in x0..x1 {
                s += src[y * cols + xx];
            }
            tmp[y * cols + x] = s / (x1 - x0) as f32;
        }
    }
    let mut out = vec![0f32; src.len()];
    for x in 0..cols {
        for y in 0..rows {
            let y0 = y.saturating_sub(r);
            let y1 = (y + r + 1).min(rows);
            let mut s = 0f32;
            for yy in y0..y1 {
                s += tmp[yy * cols + x];
            }
            out[y * cols + x] = s / (y1 - y0) as f32;
        }
    }
    out
}

/// Fixed-column-pattern removal + local mean/contrast normalization → 8-bit.
pub fn normalize(lines: &Lines) -> Vec<u8> {
    let (rows, cols) = (lines.rows, lines.cols);
    if rows == 0 {
        return Vec::new();
    }
    let mut res = lines.data.clone();
    for x in 0..cols {
        let mut m = 0f32;
        for y in 0..rows {
            m += res[y * cols + x];
        }
        m /= rows as f32;
        for y in 0..rows {
            res[y * cols + x] -= m;
        }
    }
    let mean = box_blur(&res, rows, cols, 8);
    let mut hp = vec![0f32; res.len()];
    for i in 0..res.len() {
        hp[i] = res[i] - mean[i];
    }
    let absmap: Vec<f32> = hp.iter().map(|v| v.abs()).collect();
    let scale = box_blur(&absmap, rows, cols, 8);
    let mut out = vec![0u8; res.len()];
    for i in 0..res.len() {
        let v = hp[i] / (scale[i] + 1e-3) * 48.0 + 128.0;
        out[i] = v.clamp(0.0, 255.0) as u8;
    }
    out
}

/// Crop to the finger-present band (rows whose activity exceeds a threshold),
/// bridging short gaps. Returns the row range `[start, end)`.
pub fn finger_segment(lines: &Lines) -> (usize, usize) {
    let (rows, cols) = (lines.rows, lines.cols);
    if rows == 0 {
        return (0, 0);
    }
    // per-row energy = mean |row - column-mean|
    let mut colmean = vec![0f32; cols];
    for x in 0..cols {
        let mut m = 0f32;
        for y in 0..rows {
            m += lines.data[y * cols + x];
        }
        colmean[x] = m / rows as f32;
    }
    let mut energy = vec![0f32; rows];
    for y in 0..rows {
        let mut e = 0f32;
        for x in 0..cols {
            e += (lines.data[y * cols + x] - colmean[x]).abs();
        }
        energy[y] = e / cols as f32;
    }
    let mut sorted = energy.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[rows / 2];
    let max = *sorted.last().unwrap();
    let thr = median + 0.35 * (max - median);

    let bridge = 100usize;
    let (mut best, mut best_len) = ((0usize, 0usize), 0usize);
    let mut i = 0usize;
    while i < rows {
        if energy[i] <= thr {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < rows {
            if energy[j] > thr {
                j += 1;
            } else {
                let mut k = j;
                while k < rows && energy[k] <= thr && k - j < bridge {
                    k += 1;
                }
                if k < rows && energy[k] > thr {
                    j = k;
                } else {
                    break;
                }
            }
        }
        if j - i > best_len {
            best_len = j - i;
            best = (i, j);
        }
        i = j + 1;
    }
    best
}

/// Full reconstruction: (optionally crop to the swipe) then normalize.
/// Returns (pixels, cols, rows). If cropping yields an implausibly small band
/// (< 1/8 of the input, e.g. a capture that is entirely finger data), the full
/// frame is kept instead.
/// Ridge spectral peak-to-mean of a reconstructed grayscale image.
///
/// Averages the columns into a 1-D profile and takes its magnitude spectrum; a
/// real fingerprint has a dominant peak in the ridge band (period ~8-16 px on
/// this sensor, ratio > ~1.4), while sensor noise with no finger is spectrally
/// flat (ratio near 1.0). Used with the finger-segmentation crop ratio to decide
/// whether a capture actually holds a finger.
pub fn ridge_peak(px: &[u8], w: usize, h: usize) -> f32 {
    if w < 32 || h == 0 {
        return 0.0;
    }
    // Column-mean profile (length w), mean-removed.
    let mut prof = vec![0f32; w];
    for x in 0..w {
        let mut acc = 0f32;
        for y in 0..h {
            acc += px[y * w + x] as f32;
        }
        prof[x] = acc / h as f32;
    }
    let mean = prof.iter().sum::<f32>() / w as f32;
    for v in prof.iter_mut() {
        *v -= mean;
    }
    // Hann window, then a direct DFT magnitude over the ridge frequency band.
    let band = (w / 16).max(2)..=(w / 8).max(3);
    let mut peak = 0f32;
    let mut sum = 0f32;
    let mut cnt = 0f32;
    for k in 3..w / 2 {
        let (mut re, mut im) = (0f32, 0f32);
        for (n, &v) in prof.iter().enumerate() {
            let win = 0.5 - 0.5 * (2.0 * std::f32::consts::PI * n as f32 / (w as f32 - 1.0)).cos();
            let ang = -2.0 * std::f32::consts::PI * (k * n) as f32 / w as f32;
            re += v * win * ang.cos();
            im += v * win * ang.sin();
        }
        let mag = (re * re + im * im).sqrt();
        sum += mag;
        cnt += 1.0;
        if band.contains(&k) && mag > peak {
            peak = mag;
        }
    }
    if sum == 0.0 {
        return 0.0;
    }
    peak / (sum / cnt)
}

/// Maximum rows in an image fed to libfprint. A swipe assembles into a band a few
/// hundred lines tall; a *held* finger instead stacks the same region into
/// thousands of near-identical lines, and libfprint's image drivers reject an
/// over-tall image ("unrealistically large image") before any minutiae are read.
/// Used by `window_for_feed` — NOT inside `reconstruct`, because `ridge_peak` is
/// window-size dependent and the finger gate must be computed on the full image.
pub const MAX_FEED_ROWS: usize = 500;

pub fn reconstruct(lines: &Lines, crop: bool) -> (Vec<u8>, usize, usize) {
    let seg = if crop { finger_segment(lines) } else { (0, lines.rows) };
    // Keep the detected finger band as long as it is a usable strip (>= 20 lines).
    // Captures are mostly baseline (no-finger) lines, so the band is often a small
    // fraction of the total; only fall back to the full frame if detection failed.
    let usable = seg.1 > seg.0 && (seg.1 - seg.0) >= 20;
    let (a, b) = if usable { seg } else { (0, lines.rows) };
    let cropped = Lines {
        data: lines.data[a * lines.cols..b * lines.cols].to_vec(),
        rows: b - a,
        cols: lines.cols,
    };
    let px = normalize(&cropped);
    (px, cropped.cols, cropped.rows)
}

/// Enlargement applied to a reconstructed swipe before it is fed to libfprint.
/// NBIS finds too few stable minutiae in a 200-px-wide 508 dpi strip (libfprint's
/// own narrow swipe drivers enlarge theirs for the same reason). Empirical, from
/// four recorded swipes of one finger: best genuine bozorth3 score 9 at 1x, 26 at
/// 1.5x, 14 at 2x (NOTES.md 2026-10-03).
pub const FEED_SCALE: f32 = 1.5;

/// Bilinear resize by `factor`.
pub fn upscale(px: &[u8], w: usize, h: usize, factor: f32) -> (Vec<u8>, usize, usize) {
    let (nw, nh) = ((w as f32 * factor) as usize, (h as f32 * factor) as usize);
    if w < 2 || h < 2 || nw == 0 || nh == 0 {
        return (px.to_vec(), w, h);
    }
    let mut out = Vec::with_capacity(nw * nh);
    for y in 0..nh {
        let sy = ((y as f32 + 0.5) / factor - 0.5).clamp(0.0, (h - 1) as f32);
        let y0 = (sy as usize).min(h - 2);
        let fy = sy - y0 as f32;
        for x in 0..nw {
            let sx = ((x as f32 + 0.5) / factor - 0.5).clamp(0.0, (w - 1) as f32);
            let x0 = (sx as usize).min(w - 2);
            let fx = sx - x0 as f32;
            let p = |yy: usize, xx: usize| px[yy * w + xx] as f32;
            let top = (1.0 - fx) * p(y0, x0) + fx * p(y0, x0 + 1);
            let bot = (1.0 - fx) * p(y0 + 1, x0) + fx * p(y0 + 1, x0 + 1);
            out.push(((1.0 - fy) * top + fy * bot).round() as u8);
        }
    }
    (out, nw, nh)
}

/// Prepare a reconstructed swipe for libfprint: enlarge by [`FEED_SCALE`], then
/// clamp to a central `MAX_FEED_ROWS` window (a taller image is rejected).
pub fn window_for_feed(px: &[u8], w: usize, h: usize) -> (Vec<u8>, usize, usize) {
    let (px, w, h) = upscale(px, w, h, FEED_SCALE);
    if h <= MAX_FEED_ROWS {
        return (px, w, h);
    }
    let a = (h - MAX_FEED_ROWS) / 2;
    let b = a + MAX_FEED_ROWS;
    (px[a * w..b * w].to_vec(), w, MAX_FEED_ROWS)
}

/// Write a P5 (binary) PGM.
pub fn write_pgm(path: &str, pixels: &[u8], cols: usize, rows: usize) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    write!(f, "P5\n{cols} {rows}\n255\n")?;
    f.write_all(pixels)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn identity_perm(n: usize) -> Vec<i16> {
        (0..n as i16).collect()
    }

    #[test]
    fn upscale_resizes_and_keeps_flat_areas_flat() {
        let (px, w, h) = upscale(&[200u8; 20 * 10], 20, 10, 1.5);
        assert_eq!((w, h), (30, 15));
        assert!(px.iter().all(|&v| v == 200));
    }

    #[test]
    fn unpack_mode8_scatters_via_perm() {
        // reverse perm: out[n-1-i] = src[i]
        let n = 4;
        let perm: Vec<i16> = (0..n as i16).rev().collect();
        let cfg = DliConfig { mode: 8, width: n, max_bits: 8, bits: vec![8; n], perm };
        let out = unpack_line(&[10, 20, 30, 40], &cfg);
        assert_eq!(out, vec![40, 30, 20, 10]);
    }

    #[test]
    fn unpack_mode4_nibble_expand() {
        // one byte 0xAB -> low nibble 0xB<<4 = 0xB0 at [0], high nibble 0xA0 at [1]
        let cfg = DliConfig { mode: 4, width: 2, max_bits: 8, bits: vec![8; 2], perm: identity_perm(2) };
        let out = unpack_line(&[0xAB], &cfg);
        assert_eq!(out, vec![0xB0, 0xA0]);
    }

    #[test]
    fn unpack_general_left_justifies_samples() {
        // 4-bit samples, mask 0xF, left-justified <<4. byte 0x21 -> s0=1->0x10, s1=2->0x20
        let cfg = DliConfig { mode: 6, width: 2, max_bits: 4, bits: vec![4, 4], perm: identity_perm(2) };
        let out = unpack_line(&[0x21], &cfg);
        assert_eq!(out, vec![0x10, 0x20]);
    }

    #[test]
    fn general_matches_mode8_when_8bit() {
        // with 8-bit samples the general path must equal a straight byte copy
        let n = 5;
        let src = [3u8, 250, 7, 128, 64];
        let cfg8 = DliConfig { mode: 8, width: n, max_bits: 8, bits: vec![8; n], perm: identity_perm(n) };
        let cfgg = DliConfig { mode: 99, width: n, max_bits: 8, bits: vec![8; n], perm: identity_perm(n) };
        assert_eq!(unpack_line(&src, &cfg8), unpack_line(&src, &cfgg));
    }
}
