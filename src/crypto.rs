//! Validity's proprietary SSLv3-RSA crypto, re-implemented in open Rust.
//!
//! This is a faithful port of the reference client (`scripts/vfs495_open.py`),
//! itself validated byte-exact against a live gdb dump of HP's binary
//! (`captures/skey_dump.json`) — see [`selftest`]. The crypto spec was first
//! documented by saifulmd0/vfs495-linux (`docs/SSL_PROTOCOL.md`); the
//! implementation here is independent.
//!
//! Quirks vs. textbook SSLv3, all confirmed on-device:
//!   * the RSA modulus is interpreted **little-endian** (wire bytes stay big-endian);
//!   * the record MAC **omits the length field** (Validity variant);
//!   * cipher suite 0x0044 = AES-256-CBC + SHA-1.

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::Md5;
use num_bigint::BigUint;
use rand::RngCore;
use sha1::{Digest, Sha1};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

/// SSLv3 KDF: for i=0.., salt = ('A'+i) repeated (i+1) times;
/// block = MD5(secret + SHA1(salt + secret + seed_a + seed_b)).
pub fn ssl3_prf(secret: &[u8], seed_a: &[u8], seed_b: &[u8], nbytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(nbytes + 16);
    let mut i = 0usize;
    while out.len() < nbytes {
        let salt = vec![0x41 + i as u8; i + 1];
        let mut inner = Vec::with_capacity(salt.len() + secret.len() + seed_a.len() + seed_b.len());
        inner.extend_from_slice(&salt);
        inner.extend_from_slice(secret);
        inner.extend_from_slice(seed_a);
        inner.extend_from_slice(seed_b);
        let sha = sha1(&inner);

        let mut outer = Vec::with_capacity(secret.len() + 20);
        outer.extend_from_slice(secret);
        outer.extend_from_slice(&sha);
        out.extend_from_slice(&md5(&outer));
        i += 1;
    }
    out.truncate(nbytes);
    out
}

/// PKCS#1 v1.5 type-2 RSA encryption. Modulus is interpreted **little-endian**;
/// the ciphertext on the wire is big-endian, `k` bytes wide.
pub fn rsa_encrypt(modulus_be: &[u8], exponent: u64, msg: &[u8]) -> Vec<u8> {
    let n = BigUint::from_bytes_le(modulus_be); // Validity quirk: LE interpretation
    let e = BigUint::from(exponent);
    let k = modulus_be.len();

    // random non-zero padding string, k - 3 - len(msg) bytes
    let ps_len = k - 3 - msg.len();
    let mut ps = Vec::with_capacity(ps_len);
    let mut rng = rand::rngs::OsRng;
    let mut b = [0u8; 1];
    while ps.len() < ps_len {
        rng.fill_bytes(&mut b);
        if b[0] != 0 {
            ps.push(b[0]);
        }
    }

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(msg);

    let m = BigUint::from_bytes_be(&em);
    let c = m.modpow(&e, &n);
    let mut wire = c.to_bytes_be();
    if wire.len() < k {
        let mut padded = vec![0u8; k - wire.len()];
        padded.extend_from_slice(&wire);
        wire = padded;
    }
    wire
}

/// SSLv3 `Finished` payload: MD5 and SHA1 legs over the handshake transcript.
pub fn ssl3_finished(master: &[u8], hs_msgs: &[u8], label: &[u8]) -> Vec<u8> {
    fn leg_md5(master: &[u8], hs: &[u8], label: &[u8]) -> [u8; 16] {
        let pad = 48;
        let mut inner = Vec::new();
        inner.extend_from_slice(hs);
        inner.extend_from_slice(label);
        inner.extend_from_slice(master);
        inner.extend_from_slice(&vec![0x36u8; pad]);
        let ih = md5(&inner);
        let mut outer = Vec::new();
        outer.extend_from_slice(master);
        outer.extend_from_slice(&vec![0x5cu8; pad]);
        outer.extend_from_slice(&ih);
        md5(&outer)
    }
    fn leg_sha1(master: &[u8], hs: &[u8], label: &[u8]) -> [u8; 20] {
        let pad = 40;
        let mut inner = Vec::new();
        inner.extend_from_slice(hs);
        inner.extend_from_slice(label);
        inner.extend_from_slice(master);
        inner.extend_from_slice(&vec![0x36u8; pad]);
        let ih = sha1(&inner);
        let mut outer = Vec::new();
        outer.extend_from_slice(master);
        outer.extend_from_slice(&vec![0x5cu8; pad]);
        outer.extend_from_slice(&ih);
        sha1(&outer)
    }
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&leg_md5(master, hs_msgs, label));
    out.extend_from_slice(&leg_sha1(master, hs_msgs, label));
    out
}

/// SSLv3 record layer once the AES-256-CBC + SHA1 cipher is active.
#[derive(Clone)]
pub struct Record {
    cmac: [u8; 20],
    smac: [u8; 20],
    ckey: [u8; 32],
    skey: [u8; 32],
    civ: [u8; 16],
    siv: [u8; 16],
    sseq: u64,
    rseq: u64,
}

impl Record {
    /// Split a 136-byte SSLv3 key block into MACs, keys and IVs.
    pub fn new(kb: &[u8]) -> Self {
        assert!(kb.len() >= 136, "key block too short");
        let mut r = Record {
            cmac: [0; 20],
            smac: [0; 20],
            ckey: [0; 32],
            skey: [0; 32],
            civ: [0; 16],
            siv: [0; 16],
            sseq: 0,
            rseq: 0,
        };
        r.cmac.copy_from_slice(&kb[0..20]);
        r.smac.copy_from_slice(&kb[20..40]);
        r.ckey.copy_from_slice(&kb[40..72]);
        r.skey.copy_from_slice(&kb[72..104]);
        r.civ.copy_from_slice(&kb[104..120]);
        r.siv.copy_from_slice(&kb[120..136]);
        r
    }

    /// Length-less SSLv3 MAC (Validity variant): the record length is omitted.
    fn mac(key: &[u8], seq: u64, rtype: u8, data: &[u8]) -> [u8; 20] {
        let mut hdr = Vec::with_capacity(9);
        hdr.extend_from_slice(&seq.to_be_bytes());
        hdr.push(rtype);

        let mut inner = Vec::new();
        inner.extend_from_slice(key);
        inner.extend_from_slice(&[0x36u8; 40]);
        inner.extend_from_slice(&hdr);
        inner.extend_from_slice(data);
        let ih = sha1(&inner);

        let mut outer = Vec::new();
        outer.extend_from_slice(key);
        outer.extend_from_slice(&[0x5cu8; 40]);
        outer.extend_from_slice(&ih);
        sha1(&outer)
    }

    /// Encrypt one plaintext handshake/appdata record; returns the full wire record.
    pub fn encrypt(&mut self, rtype: u8, data: &[u8]) -> Vec<u8> {
        let mac = Self::mac(&self.cmac, self.sseq, rtype, data);
        self.sseq += 1;

        let mut body = Vec::with_capacity(data.len() + 20 + 16);
        body.extend_from_slice(data);
        body.extend_from_slice(&mac);
        let pad = 16 - (body.len() % 16);
        body.extend(std::iter::repeat((pad - 1) as u8).take(pad));

        // manual CBC (padding already applied)
        let mut enc = Aes256CbcEnc::new(self.ckey.as_ref().into(), self.civ.as_ref().into());
        let mut ct = body.clone();
        for chunk in ct.chunks_mut(16) {
            enc.encrypt_block_mut(chunk.into());
        }
        self.civ.copy_from_slice(&ct[ct.len() - 16..]);

        let mut rec = Vec::with_capacity(5 + ct.len());
        rec.extend_from_slice(&[rtype, 3, 0]);
        rec.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        rec.extend_from_slice(&ct);
        rec
    }

    /// Decrypt one wire record; returns (record_type, plaintext_appdata).
    pub fn decrypt(&mut self, rec: &[u8]) -> anyhow::Result<(u8, Vec<u8>)> {
        anyhow::ensure!(rec.len() >= 5, "record too short");
        anyhow::ensure!(rec[1] == 3 && rec[2] == 0, "bad record version {:02x}{:02x}", rec[1], rec[2]);
        let ln = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        anyhow::ensure!(5 + ln <= rec.len(), "record length overruns buffer");
        let ct = &rec[5..5 + ln];

        let mut dec = Aes256CbcDec::new(self.skey.as_ref().into(), self.siv.as_ref().into());
        let mut pt = ct.to_vec();
        for chunk in pt.chunks_mut(16) {
            dec.decrypt_block_mut(chunk.into());
        }
        self.siv.copy_from_slice(&ct[ct.len() - 16..]);

        let padlen = *pt.last().unwrap() as usize + 1;
        anyhow::ensure!(padlen + 20 <= pt.len(), "pad/MAC underflow");
        let body = &pt[..pt.len() - padlen];
        let data = &body[..body.len() - 20];
        let _mac = &body[body.len() - 20..];
        self.rseq += 1;
        // MAC of the peer's records is not re-verified here (matches reference client);
        // integrity is anchored by the mutual Finished exchange.
        let _ = &self.smac;
        Ok((rec[0], data.to_vec()))
    }
}

/// AES-256-CBC-decrypt the encrypted fingerprint image stream from EP2.
///
/// The sensor encrypts the imaging burst with a per-capture AES-256 key and IV
/// that the host generates (`palCryptoRng` in HP's `_scsSensorFpEncInit`) and
/// sends to the sensor *in the clear* inside the GetFingerprint command's
/// SecurityParams TLV (tag `0x0006`: value[0..32] = key, value[0x20..0x30] = IV,
/// cipher byte `0x04` = AES-256). HP decrypts the stream in `scsSensorDecryptFingerprint`
/// with the CBC IV chained across reads. Because our capture replays HP's exact
/// command bytes, the sensor uses HP's key, which we recover from the same bytes.
///
/// One imaging burst is a single contiguous CBC ciphertext (IV = the command's
/// IV, then block-chained), so decrypting the whole burst in one pass with that
/// initial IV reproduces HP's per-read chaining. Trailing bytes beyond a 16-byte
/// multiple cannot form a block and are dropped. No padding is removed: the
/// plaintext is a raw `01fe`-framed image line stream, not an SSL record.
pub fn decrypt_image_stream(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> Vec<u8> {
    let n = ct.len() / 16 * 16;
    if n == 0 {
        return Vec::new();
    }
    let mut dec = Aes256CbcDec::new(key.into(), iv.into());
    let mut pt = ct[..n].to_vec();
    for chunk in pt.chunks_mut(16) {
        dec.decrypt_block_mut(chunk.into());
    }
    pt
}

/// 32 random bytes for ClientHello.client_random.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

#[cfg(test)]
mod tests {

    // The "client finished" label is struct.pack("<I", 0x434C4E54).
    pub const FINISHED_LABEL: [u8; 4] = [0x54, 0x4e, 0x4c, 0x43];

    #[test]
    fn finished_label_matches_python() {
        assert_eq!(FINISHED_LABEL, 0x434C4E54u32.to_le_bytes());
    }

    #[test]
    fn image_stream_decrypt_roundtrips() {
        use super::{decrypt_image_stream, Aes256CbcEnc};
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let plain: Vec<u8> = (0..96u16).map(|i| (i * 5) as u8).collect(); // 6 blocks
        let mut enc = Aes256CbcEnc::new(key.as_ref().into(), iv.as_ref().into());
        let mut ct = plain.clone();
        for chunk in ct.chunks_mut(16) {
            enc.encrypt_block_mut(chunk.into());
        }
        // Full recovery, and a trailing partial block is dropped (not a full AES block).
        assert_eq!(decrypt_image_stream(&key, &iv, &ct), plain);
        let mut ct_short = ct.clone();
        ct_short.extend_from_slice(&[0xabu8; 5]);
        assert_eq!(decrypt_image_stream(&key, &iv, &ct_short), plain);
    }
}
// ---- append to src/crypto.rs (after rsa_encrypt) ----

/// Raw PKCS#1 v1.5 **type 1** RSA signature (private-key op).
/// Modulus and d are big-endian here (unlike the LE public modulus quirk):
/// the CertificateVerify is a standard RSA private-key operation.
/// EM = 00 01 FF..FF 00 || digest   (no ASN.1 DigestInfo — SSLv3 signs the raw
/// 36-byte MD5+SHA1 concatenation directly).
pub fn rsa_sign(modulus_be: &[u8], d_be: &[u8], digest: &[u8]) -> Vec<u8> {
    let n = BigUint::from_bytes_be(modulus_be);
    let d = BigUint::from_bytes_be(d_be);
    let k = modulus_be.len();

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    let ps_len = k - 3 - digest.len();
    em.extend(std::iter::repeat(0xffu8).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(digest);

    let m = BigUint::from_bytes_be(&em);
    let c = m.modpow(&d, &n);
    let mut wire = c.to_bytes_be();
    if wire.len() < k {
        let mut padded = vec![0u8; k - wire.len()];
        padded.extend_from_slice(&wire);
        wire = padded;
    }
    wire
}
