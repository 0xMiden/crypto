// Gaussian sampler ported from fn-dsa-kgen for comparison
// This implements the CDT (Cumulative Distribution Table) approach used by fn-dsa

use alloc::vec::Vec;
use rand::Rng;

const GTAB_9: [u16; 34] = [
        1,     4,    11,    28,    65,   146,   308,   615,
     1164,  2083,  3535,  5692,  8706, 12669, 17574, 23285,
    29542, 35993, 42250, 47961, 52866, 56829, 59843, 62000,
    63452, 64371, 64920, 65227, 65389, 65470, 65507, 65524,
    65531, 65534,
];

/// Sample f or g polynomial using fn-dsa's CDT approach.
/// Ensures the returned polynomial has odd parity.
pub fn sample_f_fndsa<R: Rng>(n: usize, rng: &mut R) -> Vec<i8> {
    assert_eq!(n, 512, "Only n=512 (logn=9) is currently supported");

    let tab = &GTAB_9[..];
    let zz = 1;  // For logn=9
    let kmax = (tab.len() >> 1) as i32;

    loop {
        let mut parity = 0;
        let mut f = Vec::with_capacity(n);

        let mut i = 0;
        while i < n {
            let mut v = 0;
            for _ in 0..zz {
                // Generate random 16-bit value
                let y = (rng.next_u32() & 0xFFFF) as u32;
                v -= kmax;
                for k in 0..tab.len() {
                    v += (((tab[k] as u32).wrapping_sub(y)) >> 31) as i32;
                }
            }

            // For degree 512, value should always be in [-127, +127]
            if v < -127 || v > 127 {
                continue;
            }

            f.push(v as i8);
            i += 1;
            parity ^= v as u32;
        }

        // We need odd parity (so that the resultant of f with X^n+1 is odd)
        if (parity & 1) != 0 {
            return f;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

    struct ShakeRng<R: XofReader> {
        reader: R,
    }

    impl<R: XofReader> rand::RngCore for ShakeRng<R> {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.reader.read(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.reader.read(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.reader.read(dest);
        }
    }

    #[test]
    fn test_sample_f_fndsa_basic() {
        // Test that sampling produces valid polynomials
        let mut shake = Shake256::default();
        shake.update(b"test");
        let rng = shake.finalize_xof();
        let mut shake_rng = ShakeRng { reader: rng };

        let f = sample_f_fndsa(512, &mut shake_rng);

        assert_eq!(f.len(), 512);

        // Check all coefficients are in valid range
        for &coef in &f {
            assert!(coef >= -127 && coef <= 127);
        }

        // Check odd parity
        let parity: i32 = f.iter().map(|&x| x as i32).sum();
        assert_eq!(parity & 1, 1, "Polynomial should have odd parity");
    }
}
