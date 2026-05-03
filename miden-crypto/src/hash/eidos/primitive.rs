//! BlakeG — Goldilocks-tailored Blake2s-style compression function.
//!
//! This module knows nothing about the Miden VM, padding, or domain separation
//! — it implements only the cryptographic core: a 7-round Blake2s compression
//! with output masking suitable for lossless representation in `[Felt; 4]`.
//!
//! See `SPEC.md` (§3) for the full specification and design rationale.
//!
//! # Round count
//!
//! 7 rounds, matching BLAKE3's choice. Justified by the BLAKE3 specification
//! (§5.3), Aumasson's *Too Much Crypto* (IACR ePrint 2019/1492), and the lack
//! of cryptanalytic progress on reduced-round Blake2 since.
//!
//! # Output mask (Goldilocks-packing constraint)
//!
//! After the standard Davies–Meyer feed-forward, the top bit of words 1, 3, 5,
//! and 7 of the output cv is forced to zero. This restricts the chaining state
//! to a 252-bit subspace, enabling lossless packing into 4 Goldilocks felts via
//! `pack(lo, hi) = ((hi & 0x7fff_ffff) << 32) | lo`. See SPEC §3.3 and §3.6.

/// Standard Blake2s IV (first 32 bits of fractional parts of square roots of
/// the first 8 primes).
pub(super) const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Blake2s message-word permutation schedule, truncated to 7 rounds (matching
/// BLAKE3).
const SIGMA: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
];

/// Mask applied to odd-lane chaining-value words on output. Restricts cv to the
/// 252-bit subspace representable losslessly as `[Felt; 4]` (see SPEC §3.2,
/// §3.3 step 4).
const ODD_LANE_MASK: u32 = 0x7fff_ffff;

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// BlakeG: Goldilocks-tailored Blake2s compression function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BlakeG;

impl BlakeG {
    /// Number of rounds in the compression function.
    pub const ROUNDS: usize = 7;

    /// Number of `u32` words in the chaining value.
    pub const STATE_WORDS: usize = 8;

    /// Number of `u32` words in the message block.
    pub const BLOCK_WORDS: usize = 16;

    /// Apply BlakeG's compression function. Returns the new chaining value with the
    /// 252-bit subspace mask applied.
    ///
    /// # Input invariant
    ///
    /// The top bit of `cv[1]`, `cv[3]`, `cv[5]`, `cv[7]` must be zero (cv must
    /// live in the 252-bit subspace). This invariant is maintained by Eidos's
    /// init (§4.2 of SPEC) and preserved by this function's output mask.
    pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        debug_assert_eq!(cv[1] & !ODD_LANE_MASK, 0, "cv[1] top bit must be zero");
        debug_assert_eq!(cv[3] & !ODD_LANE_MASK, 0, "cv[3] top bit must be zero");
        debug_assert_eq!(cv[5] & !ODD_LANE_MASK, 0, "cv[5] top bit must be zero");
        debug_assert_eq!(cv[7] & !ODD_LANE_MASK, 0, "cv[7] top bit must be zero");

        // 1. Initialize working state v.
        //
        // No HAIFA per-block parameters: v[8..16] is set directly from IV[0..8].
        // The HAIFA security roles (positional uniqueness via t, finalization
        // via f) are subsumed by Eidos's init binding of `n` (SPEC §3.4).
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&cv);
        v[8..].copy_from_slice(&IV);

        // 2. Run 7 rounds of the round function.
        for round in 0..Self::ROUNDS {
            let s = &SIGMA[round];
            g(&mut v, 0, 4, 8, 12, block[s[0]], block[s[1]]);
            g(&mut v, 1, 5, 9, 13, block[s[2]], block[s[3]]);
            g(&mut v, 2, 6, 10, 14, block[s[4]], block[s[5]]);
            g(&mut v, 3, 7, 11, 15, block[s[6]], block[s[7]]);
            g(&mut v, 0, 5, 10, 15, block[s[8]], block[s[9]]);
            g(&mut v, 1, 6, 11, 12, block[s[10]], block[s[11]]);
            g(&mut v, 2, 7, 8, 13, block[s[12]], block[s[13]]);
            g(&mut v, 3, 4, 9, 14, block[s[14]], block[s[15]]);
        }

        // 3. Davies–Meyer feed-forward.
        let mut cv_new: [u32; 8] = core::array::from_fn(|i| cv[i] ^ v[i] ^ v[i + 8]);

        // 4. 252-bit subspace mask on output.
        cv_new[1] &= ODD_LANE_MASK;
        cv_new[3] &= ODD_LANE_MASK;
        cv_new[5] &= ODD_LANE_MASK;
        cv_new[7] &= ODD_LANE_MASK;

        cv_new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical 252-bit-subspace cv used across these tests (matches the SPEC
    /// init formula's unpacked u32 layout for `(domain=0, mode=0, n=0)`).
    const TEST_CV: [u32; 8] = [
        0x6a09_e667,
        0x3b67_ae85, // IV[1] with top bit cleared
        0x3c6e_f372,
        0x254f_f53a, // IV[3] (top bit already 0)
        0x0000_0000,
        0x1b05_688c, // IV[5] (top bit already 0)
        0x0000_0000,
        0x5be0_cd19, // IV[7] (top bit already 0)
    ];

    #[test]
    fn compress_output_lives_in_252_bit_subspace() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32 + 1);
        let cv_new = BlakeG::compress(TEST_CV, block);

        assert_eq!(cv_new[1] & !ODD_LANE_MASK, 0, "cv_new[1] top bit must be 0");
        assert_eq!(cv_new[3] & !ODD_LANE_MASK, 0, "cv_new[3] top bit must be 0");
        assert_eq!(cv_new[5] & !ODD_LANE_MASK, 0, "cv_new[5] top bit must be 0");
        assert_eq!(cv_new[7] & !ODD_LANE_MASK, 0, "cv_new[7] top bit must be 0");
    }

    #[test]
    fn compress_is_deterministic() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32);
        assert_eq!(BlakeG::compress(TEST_CV, block), BlakeG::compress(TEST_CV, block));
    }

    #[test]
    fn different_blocks_produce_different_outputs() {
        let block_a = [0u32; 16];
        let mut block_b = [0u32; 16];
        block_b[0] = 1;
        assert_ne!(BlakeG::compress(TEST_CV, block_a), BlakeG::compress(TEST_CV, block_b));
    }

    #[test]
    fn different_cvs_produce_different_outputs() {
        let mut cv_b = TEST_CV;
        cv_b[0] = 0;
        let block = [0u32; 16];
        assert_ne!(BlakeG::compress(TEST_CV, block), BlakeG::compress(cv_b, block));
    }
}
