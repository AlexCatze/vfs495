//! Open-source userspace driver for the Validity "Falcon" family of swipe
//! fingerprint sensors: the **VFS495** (`138a:003f`) and the **VFS471**
//! (`138a:003c`). The per-sensor differences live in [`device`]; the rest of the
//! driver is model-agnostic.
//!
//! Pipeline: [`usb`] transport → [`session`] (open SSLv3 handshake) → [`capture`]
//! (EP2 image stream) → [`image`] (DLI decode) → [`swipe`] (reconstruction) →
//! [`virtimage`] (feed libfprint's `virtual_image` for fprintd/PAM/login).
//!
//! The [`crypto`] module is validated byte-exact against a live trace; run
//! [`selftest`] to check it offline with no hardware.

pub mod calib;
pub mod capture;
pub mod crypto;
pub mod device;
pub mod image;
pub mod session;
pub mod swipe;
pub mod usb;
pub mod virtimage;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct SKeyDump {
    premaster: String,
    client_random: String,
    server_random: String,
    master: String,
    keyblock: String,
}

/// Offline crypto self-test: derive master + key block from a recorded premaster
/// and randoms, and check them byte-exact against the live gdb dump. Returns
/// `Ok(true)` on a full match. Requires `captures/skey_dump.json` (gitignored).
pub fn selftest(base: &Path) -> Result<bool> {
    let path = base.join("captures/skey_dump.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (local-only gdb dump)", path.display()))?;
    let d: SKeyDump = serde_json::from_str(&raw)?;

    let pre = hex::decode(&d.premaster)?;
    let c_rand = hex::decode(&d.client_random)?;
    let s_rand = hex::decode(&d.server_random)?;

    let master = crypto::ssl3_prf(&pre, &c_rand, &s_rand, 48);
    let kb = crypto::ssl3_prf(&master, &s_rand, &c_rand, 136);

    let ok_m = hex::encode(&master) == d.master;
    let ok_k = hex::encode(&kb) == d.keyblock;
    println!("master   match: {ok_m}");
    if !ok_m {
        println!("  got {}\n  exp {}", hex::encode(&master), d.master);
    }
    println!("keyblock match: {ok_k}");
    if !ok_k {
        println!("  got {}\n  exp {}", hex::encode(&kb), d.keyblock);
    }
    Ok(ok_m && ok_k)
}
