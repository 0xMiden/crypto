//! BlakeG — Goldilocks-tailored BLAKE3 compression function.
//!
//! This module knows nothing about the Miden VM, padding, or domain separation
//! — it implements only the cryptographic core: a 7-round BLAKE3 compression
//! with output masking suitable for lossless representation in `[Felt; 4]`.
//!
//! See `SPEC.md` (§3) for the full specification and design rationale.
//!
//! # Round count
//!
//! BlakeG uses BLAKE3's 7-round compression core, including its message schedule
//! and compression-output wiring.
//!
//! # Output mask (Goldilocks-packing constraint)
//!
//! After the 7 BLAKE3 rounds, the upper eight words of the 16-word working
//! state are XOR-folded into the lower eight words to form the next chaining
//! value. BlakeG then forces the top bit of folded words 1, 3, 5, and 7 to
//! zero. This restricts the chaining state to a 252-bit subspace, enabling
//! lossless packing into 4 Goldilocks felts via
//! `pack(lo, hi) = ((hi & 0x7fff_ffff) << 32) | lo`. See SPEC §4.2 and §5.5.

/// BLAKE3 IV.
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

/// BLAKE3 message-word schedule for the 7 compression rounds.
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Mask applied to odd-lane chaining-value words on output. Restricts cv to the
/// 252-bit subspace representable losslessly as `[Felt; 4]` (see SPEC §4.2 and
/// §5.5).
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

/// BlakeG: Goldilocks-tailored BLAKE3 compression function.
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
    /// The input chaining value may contain arbitrary `u32` lanes. The
    /// Goldilocks subspace mask is an output-finalization rule, not an input
    /// invariant.
    pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        // 1. Initialize working state v.
        //
        // BlakeG fixes the final four BLAKE3 parameter words to IV[4..8]. Eidos
        // binds domain, mode, and length into the initial chaining value.
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&cv);
        v[8..].copy_from_slice(&IV);

        // 2. Run 7 rounds of the round function.
        for round in 0..Self::ROUNDS {
            let s = &MSG_SCHEDULE[round];
            g(&mut v, 0, 4, 8, 12, block[s[0]], block[s[1]]);
            g(&mut v, 1, 5, 9, 13, block[s[2]], block[s[3]]);
            g(&mut v, 2, 6, 10, 14, block[s[4]], block[s[5]]);
            g(&mut v, 3, 7, 11, 15, block[s[6]], block[s[7]]);
            g(&mut v, 0, 5, 10, 15, block[s[8]], block[s[9]]);
            g(&mut v, 1, 6, 11, 12, block[s[10]], block[s[11]]);
            g(&mut v, 2, 7, 8, 13, block[s[12]], block[s[13]]);
            g(&mut v, 3, 4, 9, 14, block[s[14]], block[s[15]]);
        }

        // 3. Fold the upper half of the BLAKE3 working state into the lower half.
        let mut cv_new: [u32; 8] = core::array::from_fn(|i| v[i] ^ v[i + 8]);

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

    fn test_block() -> [u32; 16] {
        core::array::from_fn(|i| 0x1020_3040u32.wrapping_add((i as u32).wrapping_mul(0x0102_0304)))
    }

    fn block_words_to_bytes(block: [u32; 16]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for (word, out) in block.iter().zip(bytes.chunks_exact_mut(4)) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (word, out) in words.iter().zip(bytes.chunks_exact_mut(4)) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn reference_core_with_p(cv: [u32; 8], block: [u32; 16], p: [u32; 4]) -> [u32; 8] {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&cv);
        v[8..12].copy_from_slice(&IV[..4]);
        v[12..16].copy_from_slice(&p);

        for round in 0..BlakeG::ROUNDS {
            let s = &MSG_SCHEDULE[round];
            g(&mut v, 0, 4, 8, 12, block[s[0]], block[s[1]]);
            g(&mut v, 1, 5, 9, 13, block[s[2]], block[s[3]]);
            g(&mut v, 2, 6, 10, 14, block[s[4]], block[s[5]]);
            g(&mut v, 3, 7, 11, 15, block[s[6]], block[s[7]]);
            g(&mut v, 0, 5, 10, 15, block[s[8]], block[s[9]]);
            g(&mut v, 1, 6, 11, 12, block[s[10]], block[s[11]]);
            g(&mut v, 2, 7, 8, 13, block[s[12]], block[s[13]]);
            g(&mut v, 3, 4, 9, 14, block[s[14]], block[s[15]]);
        }

        core::array::from_fn(|i| v[i] ^ v[i + 8])
    }

    fn standard_blake3_compress(
        cv: [u32; 8],
        block: [u32; 16],
        counter: u64,
        block_len: u8,
        flags: u8,
    ) -> [u32; 8] {
        let mut out = cv;
        blake3::platform::Platform::Portable.compress_in_place(
            &mut out,
            &block_words_to_bytes(block),
            block_len,
            counter,
            flags,
        );
        out
    }

    fn mask_odd_lanes(cv: &mut [u32; 8]) {
        cv[1] &= ODD_LANE_MASK;
        cv[3] &= ODD_LANE_MASK;
        cv[5] &= ODD_LANE_MASK;
        cv[7] &= ODD_LANE_MASK;
    }

    #[test]
    fn reference_core_matches_standard_blake3_compression() {
        let cv = TEST_CV;
        let block = test_block();
        let counter = 0x0123_4567_89ab_cdefu64;
        let block_len = 64u8;
        let flags = 0x0bu8;

        let official = standard_blake3_compress(cv, block, counter, block_len, flags);
        let reference = reference_core_with_p(
            cv,
            block,
            [counter as u32, (counter >> 32) as u32, block_len as u32, flags as u32],
        );

        assert_eq!(reference, official);
    }

    #[test]
    fn standard_compression_oracle_matches_public_blake3_hash_for_one_block() {
        const CHUNK_START: u8 = 1 << 0;
        const CHUNK_END: u8 = 1 << 1;
        const ROOT: u8 = 1 << 3;

        let block = test_block();
        let bytes = block_words_to_bytes(block);
        let compressed =
            standard_blake3_compress(IV, block, 0, 64, CHUNK_START | CHUNK_END | ROOT);

        assert_eq!(words_to_bytes(compressed), *blake3::hash(&bytes).as_bytes());
    }

    #[test]
    fn blakeg_is_blake3_core_with_fixed_iv_tail_and_mask() {
        let cv = TEST_CV;
        let block = test_block();
        let mut expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        mask_odd_lanes(&mut expected);

        assert_eq!(BlakeG::compress(cv, block), expected);
    }

    #[test]
    fn compress_accepts_unmasked_input_cv_lanes() {
        let mut cv = TEST_CV;
        cv[1] |= 0x8000_0000;
        cv[3] |= 0x8000_0000;
        cv[5] |= 0x8000_0000;
        cv[7] |= 0x8000_0000;
        let block = test_block();
        let mut expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        mask_odd_lanes(&mut expected);

        assert_eq!(BlakeG::compress(cv, block), expected);
    }

    #[test]
    fn standard_blake3_compression_is_not_blakeg_mode() {
        let cv = TEST_CV;
        let block = test_block();
        let mut standard = standard_blake3_compress(cv, block, 0, 64, 0);

        mask_odd_lanes(&mut standard);

        assert_ne!(BlakeG::compress(cv, block), standard);
    }

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
