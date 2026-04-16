//! SCK v2.1 — Signature CryptoKey
//!
//! Three-layer pipeline per round:
//!   [1] Fisher-Yates permutation  — 95-char alphabet, seeded by sig+key+round via LCG
//!   [2] Caesar shift              — (perm(P) + K_byte + sig) % 95
//!   [3] ChaCha20 XOR fold        — XOR shifted value with keystream byte, then % 95
//!   [4] Sig injection            — sig char inserted at k_len % encoded_len
//!
//! Multi-round: N = ChaCha20(key, fixed_nonce)[0] % 10 + 1  →  1..=10 rounds.
//! N is key-derived (deterministic, no packet header needed).
//! Domain: printable ASCII 32..=126 (95 chars).

mod ch;
use ch::ChaCha20;

const DOM: usize = 95;
const OFF: u8    = 32;

#[inline] fn to_idx(b: u8)  -> u8 { b - OFF }
#[inline] fn to_byte(i: u8) -> u8 { i + OFF }

// ─── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed | 1) }
    #[inline]
    fn next(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    #[inline] fn bounded(&mut self, n: u64) -> u64 { self.next() % n }
}

// ─── Key / Nonce derivation ───────────────────────────────────────────────────

fn derive_key32(key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        let mut acc: u32 = (i as u32).wrapping_mul(0x45D9_F3B7);
        for (j, &b) in key.iter().enumerate() {
            acc = acc
                .wrapping_add(b as u32)
                .rotate_left((j % 31 + 1) as u32)
                ^ (b as u32).wrapping_mul(0x9E37_79B9);
        }
        out[i] = (acc ^ acc.wrapping_shr(16)) as u8;
    }
    out
}

fn derive_nonce(sig: u8, round: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    for i in 0..12u8 {
        n[i as usize] = sig
            .wrapping_mul(round.wrapping_add(1))
            .wrapping_add(i.wrapping_mul(0x1D))
            ^ sig.rotate_left((round as u32 % 8) + 1);
    }
    n[0] = sig;
    n[1] = round;
    n
}

fn derive_rounds(key32: &[u8; 32]) -> usize {
    // Dedicate a separate ChaCha20 block (counter=u32::MAX) purely for round derivation.
    // Attacker without key cannot determine N (1..=10).
    let nonce = [0xABu8; 12];
    let mut c = ChaCha20::new(key32, &nonce, u32::MAX);
    (c.next_byte() % 10 + 1) as usize
}

// ─── Signature ────────────────────────────────────────────────────────────────

fn compute_sig(data: &[u8]) -> u8 {
    let mut xf: u8  = 0x5C;
    let mut ws: u32 = 0;
    for (i, &b) in data.iter().enumerate() {
        xf ^= b.rotate_left((i % 8) as u32);
        ws  = ws.wrapping_add((b as u32).wrapping_mul(i as u32 + 1));
    }
    ((xf as u32 ^ ws) % DOM as u32) as u8
}

// ─── Permutation ──────────────────────────────────────────────────────────────

fn build_perm(sig: u8, key32: &[u8; 32], round: u8) -> [u8; 95] {
    let ksum: u64 = key32.iter().map(|&b| b as u64).sum();
    let seed = (sig as u64)
        .wrapping_mul(0xDEAD_BEEF_CAFE_0000 | round as u64)
        ^ ksum.wrapping_mul(0x0101_0101_0101_0101)
        ^ (round as u64).wrapping_mul(0x1337_C0DE_FEED_FACE);
    let mut t: [u8; 95] = core::array::from_fn(|i| i as u8);
    let mut lcg = Lcg::new(seed);
    for i in (1..95u64).rev() {
        let j = lcg.bounded(i + 1) as usize;
        t.swap(i as usize, j);
    }
    t
}

fn build_inv_perm(p: &[u8; 95]) -> [u8; 95] {
    let mut inv = [0u8; 95];
    for (i, &v) in p.iter().enumerate() { inv[v as usize] = i as u8; }
    inv
}

// ─── XOR-fold recovery ────────────────────────────────────────────────────────
//
// Enc: xored_raw = shifted ^ ks  (shifted < 95, ks ∈ 0..255)
//      c_idx     = xored_raw % 95
//
// Dec: given c_idx + same ks, find xored_raw s.t.
//      xored_raw % 95 == c_idx  AND  (xored_raw ^ ks) < 95
//
// Candidates for xored_raw: c_idx, c_idx+95, c_idx+190  (all ≤ 255)

#[warn(dead_code)] // dead code.
fn recover_xored(c_idx: u8, ks: u8) -> u8 {
    let fi = c_idx as u16;
    for m in 0..3u16 {
        let cand = fi + m * 95;
        if cand > 255 { break; }
        if (cand as u8 ^ ks) < 95 { return cand as u8; }
    }
    c_idx  // unreachable with valid inputs (proven by exhaustive test)
}

// ─── Per-character ops ────────────────────────────────────────────────────────

#[inline]
fn enc_char(p: u8, k: u8, sig: u8, perm: &[u8; 95], ks: u8) -> u8 {
    let sub  = perm[p as usize];
    ((sub as usize + k as usize + sig as usize + ks as usize) % DOM) as u8
}

#[inline]
fn dec_char(c: u8, k: u8, sig: u8, inv: &[u8; 95], ks: u8) -> u8 {
    let us = ((c as i32) - (k as i32) - (sig as i32) - (ks as i32)).rem_euclid(DOM as i32) as u8;
    inv[us as usize]
}

// ─── Single round ─────────────────────────────────────────────────────────────

fn enc_round(data: &[u8], kb: &[u8], key32: &[u8; 32], round: usize) -> Vec<u8> {
    let sig  = compute_sig(data);
    let perm = build_perm(sig, key32, round as u8);
    let mut cc = ChaCha20::new(key32, &derive_nonce(sig, round as u8), 0);
    let kl = kb.len();

    // Encrypt all bytes (all are guaranteed printable at this point)
    let mut cipher: Vec<u8> = data.iter().enumerate()
        .map(|(i, &b)| to_byte(enc_char(to_idx(b), kb[i % kl], sig, &perm, cc.next_byte())))
        .collect();

    // Variable sig injection: position = k_len % (ciphertext.len() + 1)
    // During decryption: sig_pos = k_len % encoded.len()  ← same formula, equivalent
    cipher.insert(kl % (cipher.len() + 1), to_byte(sig));
    cipher
}

fn dec_round(data: &[u8], kb: &[u8], key32: &[u8; 32], round: usize) -> Option<Vec<u8>> {
    if data.is_empty() { return None; }
    let sig_pos  = kb.len() % data.len();          // k_len % encoded.len()
    let sig_byte = data[sig_pos];
    if sig_byte < OFF || sig_byte > 126 { return None; }
    let sig = to_idx(sig_byte);

    // Strip sig to get raw ciphertext (len = data.len() - 1)
    let cipher: Vec<u8> = data.iter().enumerate()
        .filter(|&(i, _)| i != sig_pos)
        .map(|(_, &b)| b)
        .collect();

    let inv  = build_inv_perm(&build_perm(sig, key32, round as u8));
    let mut cc = ChaCha20::new(key32, &derive_nonce(sig, round as u8), 0);
    let kl = kb.len();

    // i here is the original cipher index (0..cipher.len()) matching enc_round exactly
    Some(cipher.iter().enumerate()
        .map(|(i, &b)| to_byte(dec_char(to_idx(b), kb[i % kl], sig, &inv, cc.next_byte())))
        .collect())
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` (printable ASCII 32–126) with `key`.
/// Returns `None` if any byte is outside printable range.
pub fn sck_encrypt(plaintext: &str, key: &str) -> Option<String> {
    if plaintext.is_empty() || key.is_empty() { return None; }
    if !plaintext.bytes().all(|b| (OFF..=126).contains(&b)) { return None; }
    let kb = key.as_bytes();
    let k32 = derive_key32(kb);
    let n = derive_rounds(&k32);
    let mut cur: Vec<u8> = plaintext.bytes().collect();
    for r in 1..=n { cur = enc_round(&cur, kb, &k32, r); }
    String::from_utf8(cur).ok()
}

/// Decrypt a packet produced by `sck_encrypt` with matching key.
pub fn sck_decrypt(packet: &str, key: &str) -> Option<String> {
    if packet.is_empty() || key.is_empty() { return None; }
    let kb = key.as_bytes();
    let k32 = derive_key32(kb);
    let n = derive_rounds(&k32);
    let mut cur: Vec<u8> = packet.bytes().collect();
    for r in (1..=n).rev() { cur = dec_round(&cur, kb, &k32, r)?; }
    String::from_utf8(cur).ok()
}

// ─── Round count (exposed for diagnostics) ───────────────────────────────────

pub fn round_count(key: &str) -> usize {
    derive_rounds(&derive_key32(key.as_bytes()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_alpha_only() {
        let p = sck_encrypt("HELLO", "SECRET").unwrap();
        assert_eq!(sck_decrypt(&p, "SECRET").unwrap(), "HELLO");
    }

    #[test]
    fn roundtrip_full_printable() {
        let msg = "Hello, World! SCK v2.1 @ 2025 #crypto-test";
        let p = sck_encrypt(msg, "MyK3y!@#").unwrap();
        assert_eq!(sck_decrypt(&p, "MyK3y!@#").unwrap(), msg);
    }

    #[test]
    fn roundtrip_numbers_symbols() {
        let msg = "0123456789!@#$%^&*()-=+[]{}|;:\",./<>?`~";
        let p = sck_encrypt(msg, "k3y").unwrap();
        assert_eq!(sck_decrypt(&p, "k3y").unwrap(), msg);
    }

    #[test]
    fn roundtrip_long_message() {
        let msg = "The quick brown fox jumps over the lazy dog. 1234567890!@#$%";
        let p = sck_encrypt(msg, "LONGSECRETKEY123!").unwrap();
        assert_eq!(sck_decrypt(&p, "LONGSECRETKEY123!").unwrap(), msg);
    }

    #[test]
    fn different_keys_different_output() {
        let a = sck_encrypt("ATTACK", "ALPHA").unwrap();
        let b = sck_encrypt("ATTACK", "BETA").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic() {
        assert_eq!(
            sck_encrypt("HELLO", "KEY").unwrap(),
            sck_encrypt("HELLO", "KEY").unwrap()
        );
    }

    #[test]
    fn wrong_key_fails_or_garbage() {
        let p = sck_encrypt("SECRET", "RIGHTKEY").unwrap();
        let bad = sck_decrypt(&p, "WRONGKEY");
        assert!(bad.map(|s| s != "SECRET").unwrap_or(true));
    }

    #[test]
    fn packet_length_is_msg_plus_n_rounds() {
        let msg = "HELLO";
        let key = "K";
        let n = round_count(key);
        let p = sck_encrypt(msg, key).unwrap();
        assert_eq!(p.len(), msg.len() + n, "expected len {} got {}", msg.len() + n, p.len());
    }

    #[test]
    fn recover_xored_exhaustive() {
        // Prove correctness for ALL (shifted, ks) combinations
        for shifted in 0u8..95 {
            for ks in 0u8..=255 {
                let xored_raw = shifted ^ ks;
                let c_idx     = (xored_raw as usize % DOM) as u8;
                let recovered = recover_xored(c_idx, ks);
                assert_eq!(recovered ^ ks, shifted, "shifted={shifted} ks={ks}");
            }
        }
    }

    #[test]
    fn permutation_bijective() {
        let p   = build_perm(13, &derive_key32(b"TESTKEY"), 3);
        let inv = build_inv_perm(&p);
        for i in 0u8..95 { assert_eq!(inv[p[i as usize] as usize], i); }
    }

    #[test]
    fn chacha20_rfc7539_quarter_round() {
        // RFC 7539 §2.1.1 test vector
        let mut s = [0u32; 16];
        s[0]=0x11111111; s[1]=0x01020304; s[2]=0x9b8d6f43; s[3]=0x01234567;
        ch::qr_pub(&mut s, 0, 1, 2, 3);
        assert_eq!(s[0], 0xea2a92f4);
        assert_eq!(s[1], 0xcb1cf8ce);
        assert_eq!(s[2], 0x4581472e);
        assert_eq!(s[3], 0x5881c4bb);
    }
}
