//! Swipe reconstruction: decoded scan lines → a fingerprint image at true scale.
//!
//! The sensor scans lines far faster than a finger moves, so a raw swipe is
//! stretched by an unknown, varying factor. HP's IR library (`vcsDoIR` →
//! `vcsCullScanLine` / `IRprocessScanline` / `IRreconstructImage`) solves this
//! with the sensor's second sensing line, and this module is an open
//! reimplementation of that model:
//!
//!   * Columns 0..200 of a decoded line are the **primary** line. Columns
//!     200..264 are a 64-slot **secondary** line sitting 8 pixel rows (400 µm at
//!     50 µm pitch; flex id 0x13) upstream of it, stored inverted. Secondary
//!     column `c` sits over primary pixel `c - 131`; only columns 226..=262
//!     (minus 240, 250) are live.
//!   * Lines where the finger has not moved are culled (HP's default test: keep
//!     a line once ≥ 2 primary pixels differ from the last kept line by > 25).
//!   * For each kept line, the lag `L` at which its secondary pixels match a
//!     later primary line is the time the skin takes to travel 8 rows, so the
//!     finger moves `8 / L` rows per line. Output rows are resampled at that
//!     rate (and shifted sideways by the lateral lag), one row per 50 µm.
//!
//! HP quantises the lag to 1..21 and inserts/deletes whole lines from duty-cycle
//! tables; here the lag is tracked at sub-line precision and rows are
//! interpolated. See NOTES.md 2026-10-03 for the reverse engineering.

use crate::device::Lateral;
use crate::image::{box_blur, Lines, CONTACT_SD};

/// Primary (imaging) pixels per line.
const PRI_W: usize = 200;
/// Rows between the secondary and primary lines (400 µm / 50 µm).
const SEP_ROWS: f32 = 8.0;
/// Secondary column `c` sits over primary pixel `c - SEC_TO_PRI`.
const SEC_TO_PRI: usize = 131;
/// HP's cull test: a line is kept once at least `CULL_N` of primary pixels
/// 10..190 differ from the last kept line by more than `CULL_D`.
const CULL_N: usize = 2;
const CULL_D: f32 = 25.0;
/// Lag search range (culled lines), lateral search range (pixels), NCC window.
const LAG_MIN: usize = 2;
const LAG_MAX: usize = 160;
const DX_MAX: i32 = 3;
/// Lateral range over which the drift is then measured to sub-pixel precision,
/// and the smoothing of that measurement (median, then mean, in culled lines).
const DX_REFINE: i32 = 5;
const DX_MEDIAN: usize = 31;
const DX_MEAN: usize = 61;
const WIN: usize = 31;
/// Lag tracking: max lag change per line and its per-step penalty.
const TRACK_STEP: i32 = 3;
const TRACK_LAMBDA: f32 = 0.02;
/// A lag measurement counts when its windowed NCC reaches `Q_MIN`, the
/// secondary line is on skin (row sd ≥ `SEC_CONTACT_SD`), and it is a real
/// interior peak: lag ≥ `PEAK_LAG_MIN` and the NCC halfway back to zero lag is
/// lower by `PEAK_DROP` (ridges parallel to the swipe and a resting finger give
/// profiles that only rise towards the smallest lag).
const Q_MIN: f32 = 0.5;
const SEC_CONTACT_SD: f32 = 15.0;
const PEAK_LAG_MIN: usize = 4;
const PEAK_DROP: f32 = 0.15;
/// A line this many lags away from any measurement still uses the nearest one
/// (the secondary leaves the skin ~L lines before the primary); farther away
/// there is no speed evidence and nothing is emitted.
const HOLD: f32 = 1.5;
/// Contact runs: bridge gaps up to `RUN_BRIDGE` lines, ignore runs under `RUN_MIN`.
const RUN_BRIDGE: usize = 20;
const RUN_MIN: usize = 100;
/// Fewest culled lines / lag measurements / output rows for a usable swipe.
const MIN_CULLED: usize = 30;
const MIN_GOOD: usize = 10;
const MIN_SWIPE_ROWS: usize = 64;

fn sec_cols() -> Vec<usize> {
    (226..=262).filter(|c| *c != 240 && *c != 250).collect()
}

fn median(v: &mut [f32]) -> f32 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Per-column median of `rows` (indices into `lines`) for the given columns.
fn col_median(lines: &Lines, rows: &[usize], cols: &[usize]) -> Vec<f32> {
    cols.iter()
        .map(|&x| {
            let mut col: Vec<f32> = rows.iter().map(|&y| lines.data[y * lines.cols + x]).collect();
            median(&mut col)
        })
        .collect()
}

/// Mean-remove and L2-normalise a row in place; returns its std.
fn normalize(row: &mut [f32]) -> f32 {
    let n = row.len() as f32;
    let mean = row.iter().sum::<f32>() / n;
    let mut ss = 0f32;
    for v in row.iter_mut() {
        *v -= mean;
        ss += *v * *v;
    }
    let norm = ss.sqrt() + 1e-6;
    for v in row.iter_mut() {
        *v /= norm;
    }
    (ss / n).sqrt()
}

/// `[start, end)` runs of finger contact, short gaps bridged.
fn contact_runs(sd: &[f32]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut y = 0;
    while y < sd.len() {
        if sd[y] < CONTACT_SD {
            y += 1;
            continue;
        }
        let start = y;
        while y < sd.len() && sd[y] >= CONTACT_SD {
            y += 1;
        }
        match runs.last_mut() {
            Some(last) if start - last.1 <= RUN_BRIDGE => last.1 = y,
            _ => runs.push((start, y)),
        }
    }
    runs.retain(|(a, b)| b - a >= RUN_MIN);
    runs
}

/// Lines of `[a, b)` at which the finger has moved since the last kept line.
fn cull(lines: &Lines, a: usize, b: usize) -> Vec<usize> {
    let row = |t: usize| &lines.data[t * lines.cols + 10..t * lines.cols + 190];
    let mut keep = vec![a];
    let mut last = row(a);
    for t in a + 1..b {
        let cur = row(t);
        if cur.iter().zip(last).filter(|(c, l)| (*c - *l).abs() > CULL_D).count() >= CULL_N {
            keep.push(t);
            last = cur;
        }
    }
    keep
}

/// Windowed NCC of secondary(t) against primary(t ± L), best over the lateral
/// shift. `c[t * NLAG + (L - LAG_MIN)]`.
struct Corr {
    c: Vec<f32>,
}

const NLAG: usize = LAG_MAX - LAG_MIN + 1;

/// `sec[t]`: normalised secondary rows; `pri[d][t]`: normalised primary pixels
/// under them, one entry per lateral shift searched. `forward`: secondary leads (the
/// skin reaches the primary `L` lines later).
fn correlate(sec: &[Vec<f32>], pri: &[Vec<Vec<f32>>], forward: bool) -> Corr {
    let m = sec.len();
    let mut c = vec![-2f32; m * NLAG];
    let half = WIN / 2;
    let mut d = vec![0f32; m];
    let mut cs = vec![0f32; m + 1];
    for p in pri {
        for lag in LAG_MIN..=LAG_MAX.min(m.saturating_sub(1)) {
            for t in 0..m {
                let other = if forward { t.checked_add(lag).filter(|&o| o < m) } else { t.checked_sub(lag) };
                d[t] = other.map_or(0.0, |o| sec[t].iter().zip(&p[o]).map(|(a, b)| a * b).sum());
            }
            for t in 0..m {
                cs[t + 1] = cs[t] + d[t];
            }
            for t in 0..m {
                let w = (cs[(t + half + 1).min(m)] - cs[t.saturating_sub(half)]) / WIN as f32;
                let i = t * NLAG + lag - LAG_MIN;
                c[i] = c[i].max(w);
            }
        }
    }
    Corr { c }
}

/// Sum over lines of the best NCC at any lag (which swipe direction fits).
fn direction_score(corr: &Corr) -> f32 {
    corr.c.chunks(NLAG).map(|r| r.iter().cloned().fold(f32::MIN, f32::max)).sum()
}

/// Viterbi path of the lag (as an index into `LAG_MIN..=LAG_MAX`) over all lines.
fn track(corr: &Corr, m: usize) -> Vec<usize> {
    let mut score: Vec<f32> = corr.c[..NLAG].to_vec();
    let mut back = vec![0u16; m * NLAG];
    let mut best = vec![0f32; NLAG];
    for t in 1..m {
        for i in 0..NLAG {
            let (mut bs, mut bp) = (f32::MIN, i);
            for s in -TRACK_STEP..=TRACK_STEP {
                let prev = i as i32 - s;
                if prev < 0 || prev >= NLAG as i32 {
                    continue;
                }
                let v = score[prev as usize] - TRACK_LAMBDA * s.abs() as f32;
                if v > bs {
                    bs = v;
                    bp = prev as usize;
                }
            }
            best[i] = bs + corr.c[t * NLAG + i];
            back[t * NLAG + i] = bp as u16;
        }
        score.copy_from_slice(&best);
    }
    let mut path = vec![0usize; m];
    path[m - 1] = (0..NLAG).max_by(|&a, &b| score[a].partial_cmp(&score[b]).unwrap()).unwrap();
    for t in (1..m).rev() {
        path[t - 1] = back[t * NLAG + path[t]] as usize;
    }
    path
}

/// Linear interpolation of `(xs, ys)` samples at every index `0..n`, clamped
/// at the ends (`xs` ascending).
fn interp_at_indices(n: usize, xs: &[usize], ys: &[f32]) -> Vec<f32> {
    let mut out = vec![0f32; n];
    let mut k = 0;
    for (i, o) in out.iter_mut().enumerate() {
        while k + 1 < xs.len() && xs[k + 1] <= i {
            k += 1;
        }
        *o = if i <= xs[k] || k + 1 == xs.len() {
            ys[k]
        } else {
            let f = (i - xs[k]) as f32 / (xs[k + 1] - xs[k]) as f32;
            ys[k] + f * (ys[k + 1] - ys[k])
        };
    }
    out
}

fn median_filter(x: &[f32], k: usize) -> Vec<f32> {
    let h = (k / 2) as isize;
    let n = x.len() as isize;
    (0..n)
        .map(|i| {
            let mut w: Vec<f32> = (i - h..=i + h).map(|j| x[j.clamp(0, n - 1) as usize]).collect();
            median(&mut w)
        })
        .collect()
}

fn mean_filter(x: &[f32], k: usize) -> Vec<f32> {
    let h = (k / 2) as isize;
    let n = x.len() as isize;
    (0..n).map(|i| (i - h..=i + h).map(|j| x[j.clamp(0, n - 1) as usize]).sum::<f32>() / k as f32).collect()
}

/// Flatten everything that is not finger to mid-grey, so the matcher finds no
/// minutiae in sensor noise or in the row streaks beside the finger. Finger =
/// local contrast above `MASK_SD`, of which at least half must vary along the
/// row (streaks do not).
fn mask_background(px: &mut [u8], w: usize, h: usize) {
    const MASK_SD: f32 = 18.0;
    let im: Vec<f32> = px.iter().map(|&v| v as f32).collect();
    let local = box_blur(&im, h, w, 7);
    let mut along = vec![0f32; im.len()];
    for y in 0..h {
        let row = &im[y * w..(y + 1) * w];
        for x in 0..w {
            let (x0, x1) = (x.saturating_sub(4), (x + 5).min(w));
            along[y * w + x] = row[x] - row[x0..x1].iter().sum::<f32>() / (x1 - x0) as f32;
        }
    }
    let energy = |hp: Vec<f32>| -> Vec<f32> {
        let sq: Vec<f32> = hp.iter().map(|v| v * v).collect();
        box_blur(&sq, h, w, 7).iter().map(|v| v.sqrt()).collect()
    };
    let e = energy(im.iter().zip(&local).map(|(a, b)| a - b).collect());
    let ex = energy(along);
    let finger: Vec<f32> =
        e.iter().zip(&ex).map(|(&a, &b)| if a > MASK_SD && b > MASK_SD * 0.5 { 1.0 } else { 0.0 }).collect();
    // Background = non-finger pixels reachable from the image border; a
    // low-contrast patch inside the finger stays as it is (a grey hole there
    // would itself look like ridge endings).
    let open: Vec<bool> = box_blur(&finger, h, w, 5).iter().map(|&f| f <= 0.5).collect();
    let mut background = vec![false; px.len()];
    let mut stack: Vec<usize> = (0..w)
        .flat_map(|x| [x, (h - 1) * w + x])
        .chain((0..h).flat_map(|y| [y * w, y * w + w - 1]))
        .collect();
    while let Some(i) = stack.pop() {
        if !open[i] || background[i] {
            continue;
        }
        background[i] = true;
        let (x, y) = (i % w, i / w);
        if x > 0 {
            stack.push(i - 1);
        }
        if x + 1 < w {
            stack.push(i + 1);
        }
        if y > 0 {
            stack.push(i - w);
        }
        if y + 1 < h {
            stack.push(i + w);
        }
    }
    for (p, bg) in px.iter_mut().zip(background) {
        if bg {
            *p = 128;
        }
    }
}

/// Reconstruct one contact run `[a, b)` into rows of `PRI_W` background-removed
/// pixels, one row per 50 µm of skin. `bg_pri` / `bg_sec`: whole-capture
/// per-column medians (the sensor's fixed pattern).
fn reconstruct_run(lines: &Lines, a: usize, b: usize, bg_pri: &[f32], bg_sec: &[f32], lateral: Lateral) -> Option<Vec<Vec<f32>>> {
    let keep = cull(lines, a, b);
    let m = keep.len();
    if m < MIN_CULLED {
        return None;
    }
    let scols = sec_cols();
    let at = |t: usize, x: usize| lines.data[keep[t] * lines.cols + x];

    // Normalised secondary rows (inverted) and the primary pixels under them.
    let run_bg_sec = col_median(lines, &keep, &scols);
    let all_cols: Vec<usize> = (0..PRI_W).collect();
    let run_bg_pri = col_median(lines, &keep, &all_cols);
    let sec: Vec<Vec<f32>> = (0..m)
        .map(|t| {
            let mut r: Vec<f32> = scols.iter().zip(&run_bg_sec).map(|(&c, bg)| bg - at(t, c)).collect();
            normalize(&mut r);
            r
        })
        .collect();
    let pri: Vec<Vec<Vec<f32>>> = (-DX_REFINE..=DX_REFINE)
        .map(|dx| {
            (0..m)
                .map(|t| {
                    let mut r: Vec<f32> = scols
                        .iter()
                        .map(|&c| {
                            let x = (c as i32 - SEC_TO_PRI as i32 + dx) as usize;
                            at(t, x) - run_bg_pri[x]
                        })
                        .collect();
                    normalize(&mut r);
                    r
                })
                .collect()
        })
        .collect();

    // Swipe direction = whichever lag sign correlates better; then track the lag.
    let search = &pri[(DX_REFINE - DX_MAX) as usize..=(DX_REFINE + DX_MAX) as usize];
    let fwd = correlate(&sec, search, true);
    let rev = correlate(&sec, search, false);
    let forward = direction_score(&fwd) >= direction_score(&rev);
    let corr = if forward { fwd } else { rev };
    let path = track(&corr, m);
    let c = |t: usize, i: usize| corr.c[t * NLAG + i];

    // Which lines carry a trustworthy lag measurement.
    let mut good_idx = Vec::new();
    let mut good_lag = Vec::new();
    for (t, &i) in path.iter().enumerate() {
        let lag = i + LAG_MIN;
        let q = c(t, i);
        let mut srow: Vec<f32> = scols.iter().zip(bg_sec).map(|(&x, bg)| bg - at(t, x)).collect();
        let sec_contact = normalize(&mut srow) >= SEC_CONTACT_SD;
        // half the lag, rounded half-to-even, floored at the smallest lag
        let half = (if lag % 4 == 3 { lag / 2 + 1 } else { lag / 2 }).max(LAG_MIN);
        let distinct = lag >= PEAK_LAG_MIN && q - c(t, half - LAG_MIN) >= PEAK_DROP;
        if q >= Q_MIN && sec_contact && distinct {
            // sub-line refinement: parabola through the peak
            let mut lf = lag as f32;
            if i > 0 && i + 1 < NLAG {
                let (y0, y1, y2) = (c(t, i - 1), q, c(t, i + 1));
                let den = y0 - 2.0 * y1 + y2;
                if den < 0.0 {
                    lf += 0.5 * (y0 - y2) / den;
                }
            }
            good_idx.push(t);
            good_lag.push(lf);
        }
    }
    if good_idx.len() < MIN_GOOD {
        return None;
    }
    let lag = median_filter(&interp_at_indices(m, &good_idx, &good_lag), 5);

    // Lateral drift, to sub-pixel precision: at each line's lag, the windowed NCC
    // as a function of the lateral shift, parabola-refined at its peak. An
    // integer shift is far too coarse — one pixel over a typical lag is a shear
    // of ~0.12 px per row.
    let half = WIN / 2;
    let mut ncc_by_dx = vec![vec![0f32; m]; pri.len()];
    for (p, out) in pri.iter().zip(ncc_by_dx.iter_mut()) {
        let mut cs = vec![0f32; m + 1];
        for t in 0..m {
            let l = lag[t].round() as usize;
            let other = if forward { (t + l).min(m - 1) } else { t.saturating_sub(l) };
            cs[t + 1] = cs[t] + sec[t].iter().zip(&p[other]).map(|(a, b)| a * b).sum::<f32>();
        }
        for (t, o) in out.iter_mut().enumerate() {
            *o = (cs[(t + half + 1).min(m)] - cs[t.saturating_sub(half)]) / WIN as f32;
        }
    }
    let good_dx: Vec<f32> = good_idx
        .iter()
        .map(|&t| {
            let q = |d: usize| ncc_by_dx[d][t];
            let peak = (0..pri.len()).max_by(|&a, &b| q(a).partial_cmp(&q(b)).unwrap()).unwrap();
            let d = peak.clamp(1, pri.len() - 2);
            let den = q(d - 1) - 2.0 * q(d) + q(d + 1);
            let frac = if den < 0.0 { (0.5 * (q(d - 1) - q(d + 1)) / den).clamp(-0.5, 0.5) } else { 0.0 };
            d as f32 - DX_REFINE as f32 + frac
        })
        .collect();
    let dx = mean_filter(&median_filter(&interp_at_indices(m, &good_idx, &good_dx), DX_MEDIAN), DX_MEAN);

    // Lateral-drift handling (`lateral`, from the device profile). Integrating
    // `dx/l` row-by-row turns any constant bias in the drift estimate into a
    // linearly growing sideways shift — a shear/rotation of the whole print
    // (confirmed on the VFS471 2026-10-25: the raw decode is laterally straight,
    // `Full` sheared it ~30°, and `None` restores upright, full-width prints that
    // match far better). `Detrend` removes only the DC bias (keeps genuine drift
    // variation); `Full` accumulates everything (the original VFS495 behavior).
    let drift_rate: Vec<f32> = (0..m)
        .map(|t| {
            let l = lag[t].max(1.0);
            dx[t] / l
        })
        .collect();
    let mean_rate = {
        let mut moving_rates = Vec::new();
        let mut g = 0;
        for t in 0..m {
            while g + 1 < good_idx.len() && good_idx[g + 1].abs_diff(t) <= good_idx[g].abs_diff(t) {
                g += 1;
            }
            if (good_idx[g].abs_diff(t) as f32) <= HOLD * lag[t] {
                moving_rates.push(drift_rate[t]);
            }
        }
        if moving_rates.is_empty() { 0.0 } else { moving_rates.iter().sum::<f32>() / moving_rates.len() as f32 }
    };

    // Skin position (rows) and lateral offset (pixels) of every kept line.
    let mut y = vec![0f32; m];
    let mut xs = vec![0f32; m];
    let mut g = 0;
    for t in 0..m {
        while g + 1 < good_idx.len() && good_idx[g + 1].abs_diff(t) <= good_idx[g].abs_diff(t) {
            g += 1;
        }
        let l = lag[t].max(1.0);
        let moving = good_idx[g].abs_diff(t) as f32 <= HOLD * lag[t];
        let step = match lateral {
            Lateral::None => 0.0,
            Lateral::Full => drift_rate[t],
            Lateral::Detrend => drift_rate[t] - mean_rate,
        };
        if t + 1 < m {
            y[t + 1] = y[t] + if moving { SEP_ROWS / l } else { 0.0 };
            xs[t + 1] = xs[t] + if moving { step } else { 0.0 };
        }
    }

    // Resample the primary line at integer skin rows.
    let n_out = y[m - 1].floor() as usize + 1;
    let mut out = Vec::with_capacity(n_out);
    let mut i = 0;
    for k in 0..n_out {
        while i + 2 < m && y[i + 1] <= k as f32 {
            i += 1;
        }
        let f = ((k as f32 - y[i]) / (y[i + 1] - y[i]).max(1e-9)).clamp(0.0, 1.0);
        let shift = (1.0 - f) * xs[i] + f * xs[i + 1];
        let px = |x: usize| {
            let (p0, p1) = (at(i, x) - bg_pri[x], at(i + 1, x) - bg_pri[x]);
            (1.0 - f) * p0 + f * p1
        };
        let row: Vec<f32> = (0..PRI_W)
            .map(|x| {
                let sx = (x as f32 + shift).clamp(0.0, (PRI_W - 1) as f32);
                let x0 = (sx.floor() as usize).min(PRI_W - 2);
                let fx = sx - x0 as f32;
                (1.0 - fx) * px(x0) + fx * px(x0 + 1)
            })
            .collect();
        out.push(row);
    }
    if !forward {
        out.reverse();
    }
    Some(out)
}

/// Reconstruct a swipe into a fingerprint image with one row per 50 µm of skin
/// (square pixels, independent of swipe speed). A capture spans two swipe
/// windows; the contact run yielding the most rows wins. Returns
/// `(pixels, width, height)`, or `None` without a usable swipe (blank sensor,
/// or a finger that touched but did not move).
pub fn reconstruct_swipe(lines: &Lines, lateral: Lateral) -> Option<(Vec<u8>, usize, usize)> {
    if lines.cols < 264 || lines.rows == 0 {
        return None;
    }
    let all_rows: Vec<usize> = (0..lines.rows).collect();
    let pri_cols: Vec<usize> = (0..PRI_W).collect();
    let bg_pri = col_median(lines, &all_rows, &pri_cols);
    let bg_sec = col_median(lines, &all_rows, &sec_cols());
    let best = contact_runs(&lines.contact_sd())
        .into_iter()
        .filter_map(|(a, b)| reconstruct_run(lines, a, b, &bg_pri, &bg_sec, lateral))
        .max_by_key(|rows| rows.len())?;
    if best.len() < MIN_SWIPE_ROWS {
        return None;
    }
    // Global 1st-99th percentile contrast stretch.
    let mut all: Vec<f32> = best.iter().flat_map(|r| r.iter().copied()).collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (lo, hi) = (all[all.len() / 100], all[all.len() * 99 / 100]);
    let span = (hi - lo).max(1e-3);
    let mut px: Vec<u8> = best
        .iter()
        .flat_map(|r| r.iter().map(|&v| ((v - lo) / span * 255.0).clamp(0.0, 255.0) as u8))
        .collect();
    mask_background(&mut px, PRI_W, best.len());
    Some((px, PRI_W, best.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skin texture: three ridge systems of different period and direction, so
    /// no vertical shift other than zero maps the texture onto itself.
    fn skin(y: f32, x: f32) -> f32 {
        let wave = |fx: f32, fy: f32, period: f32| ((fx * x + fy * y) * std::f32::consts::TAU / period).sin();
        128.0 + 30.0 * wave(0.8, 0.6, 9.0) + 25.0 * wave(-0.5, 0.87, 12.3) + 20.0 * wave(0.26, 0.97, 7.1)
    }

    /// Synthetic capture: `blank` quiet lines, then a finger moving `speed` skin
    /// rows per line for `moving` lines. The secondary line sees the skin 8 rows
    /// ahead of the primary, inverted.
    fn swipe_lines(blank: usize, moving: usize, speed: f32) -> Lines {
        let cols = 264;
        let mut data = Vec::new();
        for t in 0..blank + moving {
            for x in 0..cols {
                let v = if t < blank {
                    128.0 + ((x * 7 + t * 3) % 5) as f32
                } else if x < PRI_W {
                    skin((t - blank) as f32 * speed, x as f32)
                } else {
                    255.0 - skin((t - blank) as f32 * speed + SEP_ROWS, (x - SEC_TO_PRI) as f32)
                };
                data.push(v);
            }
        }
        Lines { data, rows: blank + moving, cols }
    }

    #[test]
    fn height_is_independent_of_swipe_speed() {
        // The same 300 rows of skin, swiped at two speeds.
        let (_, w, slow) = reconstruct_swipe(&swipe_lines(4000, 3000, 0.1), Lateral::Full).expect("slow swipe");
        let (_, _, fast) = reconstruct_swipe(&swipe_lines(4000, 1000, 0.3), Lateral::Full).expect("fast swipe");
        assert_eq!(w, PRI_W);
        assert!((270..=315).contains(&slow), "slow swipe height {slow}");
        assert!((270..=315).contains(&fast), "fast swipe height {fast}");
    }

    #[test]
    fn held_finger_and_blank_are_rejected() {
        // Held still: contact but no motion.
        assert!(reconstruct_swipe(&swipe_lines(4000, 3000, 0.0), Lateral::Full).is_none());
        // Blank sensor.
        assert!(reconstruct_swipe(&swipe_lines(7000, 0, 0.0), Lateral::Full).is_none());
        assert_eq!(swipe_lines(7000, 0, 0.0).contact_rows(CONTACT_SD), 0);
    }
}
