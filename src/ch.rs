//! ch.rs — ChaCha20 keystream generator.
//! RFC 7539 compliant. no_std compatible. Zero dependencies.

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

pub struct ChaCha20 {
    init:  [u32; 16],
    block: [u8; 64],
    pos:   usize,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        #[inline] fn w(s: &[u8]) -> u32 { u32::from_le_bytes([s[0],s[1],s[2],s[3]]) }
        let init = [
            0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,  // "expand 32-byte k"
            w(&key[0..]),  w(&key[4..]),  w(&key[8..]),  w(&key[12..]),
            w(&key[16..]), w(&key[20..]), w(&key[24..]), w(&key[28..]),
            counter,
            w(&nonce[0..]), w(&nonce[4..]), w(&nonce[8..]),
        ];
        let mut c = Self { init, block: [0u8; 64], pos: 64 };
        c.refill();
        c
    }

    fn refill(&mut self) {
        let mut s = self.init;
        for _ in 0..10 {
            qr(&mut s,0,4, 8,12); qr(&mut s,1,5, 9,13);
            qr(&mut s,2,6,10,14); qr(&mut s,3,7,11,15);
            qr(&mut s,0,5,10,15); qr(&mut s,1,6,11,12);
            qr(&mut s,2,7, 8,13); qr(&mut s,3,4, 9,14);
        }
        for i in 0..16 {
            let word = s[i].wrapping_add(self.init[i]);
            self.block[i*4..i*4+4].copy_from_slice(&word.to_le_bytes());
        }
        self.init[12] = self.init[12].wrapping_add(1);
        self.pos = 0;
    }

    #[inline]
    pub fn next_byte(&mut self) -> u8 {
        if self.pos >= 64 { self.refill(); }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }
}

/// Exposed only for tests — verifies RFC 7539 §2.1.1 quarter-round vector.
#[cfg(test)]
pub fn qr_pub(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    qr(s, a, b, c, d);
}
