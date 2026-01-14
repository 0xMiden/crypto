// Gaussian sampler ported from fn-dsa-kgen for comparison
// This implements the CDT (Cumulative Distribution Table) approach used by fn-dsa

use alloc::vec::Vec;

use fn_dsa_comm::PRNG;

const GTAB_9: [u16; 34] = [
    1, 4, 11, 28, 65, 146, 308, 615, 1164, 2083, 3535, 5692, 8706, 12669, 17574, 23285, 29542,
    35993, 42250, 47961, 52866, 56829, 59843, 62000, 63452, 64371, 64920, 65227, 65389, 65470,
    65507, 65524, 65531, 65534,
];

/// Sample f or g polynomial using fn-dsa's CDT approach.
/// Ensures the returned polynomial has odd parity.
pub fn sample_f_fndsa<R: PRNG>(n: usize, rng: &mut R) -> Vec<i8> {
    assert_eq!(n, 512, "Only n=512 (logn=9) is currently supported");

    let tab = &GTAB_9[..];
    let zz = 1; // For logn=9
    let kmax = (tab.len() >> 1) as i32;

    loop {
        let mut parity = 0;
        let mut f = Vec::with_capacity(n);

        let mut i = 0;
        while i < n {
            let mut v = 0;
            for _ in 0..zz {
                // Generate random 16-bit value (exactly as fn-dsa does)
                let y = rng.next_u16() as u32;
                v -= kmax;
                for &t in tab {
                    v += (((t as u32).wrapping_sub(y)) >> 31) as i32;
                }
            }

            // For degree 512, value should always be in [-127, +127]
            if !(-127..=127).contains(&v) {
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
    use fn_dsa_comm::{PRNG, shake::SHAKE256_PRNG};

    use super::*;

    #[test]
    fn test_sample_f_fndsa_basic() {
        // Test that sampling produces valid polynomials
        let mut rng = <SHAKE256_PRNG as PRNG>::new(b"test");

        let f = sample_f_fndsa(512, &mut rng);

        assert_eq!(f.len(), 512);

        // Check all coefficients are in valid range
        for &coef in &f {
            assert!(coef >= -127);
        }

        // Check odd parity
        let parity: i32 = f.iter().map(|&x| x as i32).sum();
        assert_eq!(parity & 1, 1, "Polynomial should have odd parity");
    }
}
