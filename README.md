# SCK v2.1 — Signature CryptoKey

> ONLY FOR EDUCATION PURPOSE ONLY.

Multi-layer symmetric cipher. Full printable ASCII. Zero dependencies. Pure safe Rust.

---

## What's New in v2.1

| Feature | v1 | v2 | **v2.1** |
|---|---|---|---|
| Domain | A–Z only | A–Z only | **All printable ASCII (95 chars)** |
| Substitution | Direct shift | Fisher-Yates (A–Z) | **Fisher-Yates (95-char)** |
| XOR | ✗ | XOR mod 26 | **ChaCha20 keystream XOR fold (reversible, proven)** |
| Multi-round | ✗ | ✗ | **N = 1..=10 rounds, key-derived** |
| Keystream | ✗ | ✗ | **Hand-rolled ChaCha20 (RFC 7539, no_std)** |
| Binary size | std | std | **`opt-level=z` + LTO + strip + panic=abort** |

---

## Pipeline (per round, per character)

```
P[i]
 │  [1] Fisher-Yates substitution
 │      perm[P[i]]   — 95-char alphabet shuffled by LCG(sig, key32, round)
 │
 │  [2] Caesar shift
 │      (perm[P[i]] + K_byte[i % |K|] + sig) % 95
 │
 │  [3] ChaCha20 XOR fold
 │      shifted ^ ks_byte  →  % 95  →  C[i]
 │      (reversible: recover_xored finds unique preimage)
 │
 │  [4] Sig injection
 │      sig char inserted at k_len % (cipher_len + 1)
 ▼
C[i]  (printable ASCII 32–126)
```

Decryption: exact reverse — strip sig → un-XOR → un-shift → inv-perm.

---

## Multi-round

```
N = ChaCha20(key32, nonce=0xAB..., counter=0xFFFFFFFF)[0] % 10 + 1
```

- Same key → always same N (1..=10)
- Attacker without key cannot determine N
- Each round uses a fresh (sig, round)-derived nonce → unique keystream per round
- Packet length = `plaintext.len() + N` (each round adds 1 sig byte)

---

## Quick Start

```bash
# Encrypt
cargo run --release -- encrypt "Hello, World! #2025" "MySecretKey"
# → Rounds : 7
# → Packet : <printable ASCII string>

# Decrypt
cargo run --release -- decrypt "<PACKET>" "MySecretKey"
# → Plain  : Hello, World! #2025

# Check round count for a key
cargo run --release -- info "MySecretKey"
# → Rounds : 7

# Tests
cargo test

# Build lean binary
cargo build --release
# Binary at: target/release/sckv2_1
```

---

## File Structure

```
sck-crypto/
├── Cargo.toml                  # release: opt-level=z, lto, strip, panic=abort
├── README.md
└── src/
    ├── ch.rs                   # ChaCha20 — RFC 7539, no_std compatible
    ├── lib.rs                  # SCK core: LCG, sig, perm, enc/dec, API
    └── sckv2_1.rs              # CLI binary
```

---

## Security Notice

SCK is **educational** — symmetric, A-Z+ASCII, not hardened against side-channels.  
For production: **AES-256-GCM** or **ChaCha20-Poly1305** (with authenticated encryption).

---

## License

Apache2
