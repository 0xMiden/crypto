//! Goldilocks-tailored BLAKE3 compression.
//!
//! BlakeG uses BLAKE3's 7-round compression core with fixed parameter words.
//! `compress` reduces each raw 64-bit output pair modulo the Goldilocks prime
//! so the 8-word chaining value packs into four canonical field elements.
//! Reducing a uniform 64-bit word modulo `p = 2^64 - 2^32 + 1` is not uniform:
//! the low `2^32 - 1` residues have two preimages. Treat each finalized Felt as
//! having at most 63 bits of min-entropy.

mod blake3_schedule;

use crate::Felt;

#[cfg(test)]
pub(super) const IV: [u32; 8] = blake3_schedule::IV;
pub(super) const PACKED_LANES: usize = blake3_schedule::PACKED_LANES;

#[inline(always)]
fn reduce_u32_pair(lo: u32, hi: u32) -> (u32, u32) {
    let value = ((hi as u64) << 32) | lo as u64;
    let reduced = if value >= Felt::ORDER {
        value - Felt::ORDER
    } else {
        value
    };
    (reduced as u32, (reduced >> 32) as u32)
}

#[inline(always)]
fn finalize_output(mut cv: [u32; 8]) -> [u32; 8] {
    (cv[0], cv[1]) = reduce_u32_pair(cv[0], cv[1]);
    (cv[2], cv[3]) = reduce_u32_pair(cv[2], cv[3]);
    (cv[4], cv[5]) = reduce_u32_pair(cv[4], cv[5]);
    (cv[6], cv[7]) = reduce_u32_pair(cv[6], cv[7]);
    cv
}

#[inline(always)]
#[cfg(any(test, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
fn finalize_packed_output_scalar<const LANES: usize>(
    mut cv: [[u32; LANES]; 8],
) -> [[u32; LANES]; 8] {
    for word in 0..4 {
        for lane in 0..LANES {
            (cv[2 * word][lane], cv[2 * word + 1][lane]) =
                reduce_u32_pair(cv[2 * word][lane], cv[2 * word + 1][lane]);
        }
    }
    cv
}

#[inline(always)]
#[cfg(test)]
fn finalize_packed_output<const LANES: usize>(cv: [[u32; LANES]; 8]) -> [[u32; LANES]; 8] {
    finalize_packed_output_scalar(cv)
}

#[inline(always)]
#[cfg(any(feature = "internal", test))]
#[cfg_attr(feature = "internal", allow(dead_code))]
fn finalize_packed_output_4(cv: [[u32; 4]; 8]) -> [[u32; 4]; 8] {
    packed_finalizer::finalize_4(cv)
}

#[inline(always)]
fn finalize_packed_output_native(cv: [[u32; PACKED_LANES]; 8]) -> [[u32; PACKED_LANES]; 8] {
    packed_finalizer::finalize_native(cv)
}

/// Goldilocks-tailored BLAKE3 compression.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct BlakeG;

impl BlakeG {
    /// Applies BlakeG and reduces each output pair to a canonical field element.
    ///
    /// The input chaining value may contain arbitrary `u32` lanes. The
    /// Goldilocks reduction is an output-finalization rule, not an input
    /// invariant.
    pub(super) fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        finalize_output(Self::compress_raw(cv, block))
    }

    /// Apply BlakeG's compression function before Goldilocks output reduction.
    ///
    /// Returns the eight folded BLAKE3/BlakeG output words:
    ///
    /// ```text
    /// out[i] = v[i] ^ v[i + 8]
    /// ```
    ///
    /// These are the words consumed by [`Self::compress`] before modular reduction.
    /// This is a raw compression output, not an Eidos digest. Callers that use
    /// BlakeG as a hash must bind domain, mode, and length into the input CV.
    pub fn compress_raw(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        blake3_schedule::compress_raw(cv, block)
    }

    /// Apply BlakeG and return the full 16-word XOF output (low half || high
    /// half), before Goldilocks output reduction.
    ///
    /// ```text
    /// out[i]     = v[i] ^ v[i + 8]    (i in 0..8)   // standard CV fold (low half)
    /// out[i + 8] = v[i + 8] ^ cv[i]   (i in 0..8)   // BLAKE3 XOF feed-forward (high half)
    /// ```
    ///
    /// The low half is [`Self::compress_raw`]. The high half is BLAKE3's XOF
    /// feed-forward. This is raw XOF material, not a canonical field digest.
    /// Callers that use it as XOF output must bind domain, mode, and length
    /// into the input CV.
    pub fn compress_raw_xof(cv: [u32; 8], block: [u32; 16]) -> [u32; 16] {
        blake3_schedule::compress_raw_xof(cv, block)
    }

    /// Apply BlakeG to several independent lanes with the same instruction stream.
    ///
    /// Lane `i` of the result is identical to `compress(cv_i, block_i)`, where
    /// `cv_i[j] = cv[j][i]` and `block_i[j] = block[j][i]`.
    #[cfg(test)]
    fn compress_packed<const LANES: usize>(
        cv: [[u32; LANES]; 8],
        block: [[u32; LANES]; 16],
    ) -> [[u32; LANES]; 8] {
        finalize_packed_output(blake3_schedule::compress_packed(cv, block))
    }

    /// Apply BlakeG to four independent lanes.
    ///
    /// On `aarch64`, this uses NEON. On `x86_64`, this uses SSE2. Other targets
    /// fall back to the portable packed implementation.
    #[cfg(any(feature = "internal", test))]
    #[cfg_attr(feature = "internal", allow(dead_code))]
    #[inline]
    pub(super) fn compress_packed_4(cv: [[u32; 4]; 8], block: [[u32; 4]; 16]) -> [[u32; 4]; 8] {
        finalize_packed_output_4(blake3_schedule::compress_packed_4(cv, block))
    }

    /// Apply BlakeG to the build's selected native packed lane width.
    #[inline]
    pub(super) fn compress_packed_native(
        cv: [[u32; PACKED_LANES]; 8],
        block: [[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        finalize_packed_output_native(blake3_schedule::compress_packed_native(cv, block))
    }

    #[cfg(feature = "internal")]
    #[allow(dead_code)]
    pub(super) fn compress_packed_4_rotr8_shift(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        finalize_packed_output_4(blake3_schedule::compress_packed_4_rotr8_shift(cv, block))
    }

    #[cfg(feature = "internal")]
    #[allow(dead_code)]
    pub(super) fn compress_packed_4_rotr8_cached(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        finalize_packed_output_4(blake3_schedule::compress_packed_4_rotr8_cached(cv, block))
    }

    #[cfg(feature = "internal")]
    #[allow(dead_code)]
    pub(super) fn compress_packed_4_preloaded_messages(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        finalize_packed_output_4(blake3_schedule::compress_packed_4_preloaded_messages(cv, block))
    }
}

mod packed_finalizer {
    use super::PACKED_LANES;

    // For p = 0xffff_ffff_0000_0001, a 64-bit pair `hi:lo` needs reduction
    // exactly when `hi == u32::MAX && lo != 0`; the reduced pair is `(lo - 1, 0)`.

    #[cfg(any(
        feature = "internal",
        test,
        not(all(
            target_arch = "x86_64",
            any(target_feature = "avx2", target_feature = "avx512f"),
        )),
    ))]
    #[inline(always)]
    pub(super) fn finalize_4(cv: [[u32; 4]; 8]) -> [[u32; 4]; 8] {
        #[cfg(target_arch = "aarch64")]
        {
            return neon::finalize_4(cv);
        }

        #[cfg(target_arch = "x86_64")]
        {
            return x86_64_sse2::finalize_4(cv);
        }

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            super::finalize_packed_output_scalar(cv)
        }
    }

    #[inline(always)]
    pub(super) fn finalize_native(cv: [[u32; PACKED_LANES]; 8]) -> [[u32; PACKED_LANES]; 8] {
        native_backend::finalize(cv)
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    mod native_backend {
        pub(super) fn finalize(cv: [[u32; 16]; 8]) -> [[u32; 16]; 8] {
            super::x86_64_avx512::finalize_16(cv)
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(target_feature = "avx512f")))]
    mod native_backend {
        pub(super) fn finalize(cv: [[u32; 8]; 8]) -> [[u32; 8]; 8] {
            super::x86_64_avx2::finalize_8(cv)
        }
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "x86_64", target_feature = "avx512f"),
    )))]
    mod native_backend {
        use super::finalize_4;

        pub(super) fn finalize(cv: [[u32; 4]; 8]) -> [[u32; 4]; 8] {
            finalize_4(cv)
        }
    }

    #[cfg(all(
        target_arch = "x86_64",
        any(
            feature = "internal",
            test,
            not(any(target_feature = "avx2", target_feature = "avx512f")),
        ),
    ))]
    mod x86_64_sse2 {
        use core::arch::x86_64::*;

        #[inline(always)]
        fn load(xs: &[u32; 4]) -> __m128i {
            unsafe { _mm_loadu_si128(xs.as_ptr().cast()) }
        }

        #[inline(always)]
        fn store(x: __m128i) -> [u32; 4] {
            let mut out = [0u32; 4];
            unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), x) };
            out
        }

        #[inline(always)]
        fn reduce_pair(lo: __m128i, hi: __m128i) -> (__m128i, __m128i) {
            unsafe {
                let zero = _mm_setzero_si128();
                let ones = _mm_set1_epi32(-1);
                let reduce = _mm_andnot_si128(_mm_cmpeq_epi32(lo, zero), _mm_cmpeq_epi32(hi, ones));
                let lo = _mm_sub_epi32(lo, _mm_and_si128(reduce, _mm_set1_epi32(1)));
                let hi = _mm_andnot_si128(reduce, hi);
                (lo, hi)
            }
        }

        pub(super) fn finalize_4(mut cv: [[u32; 4]; 8]) -> [[u32; 4]; 8] {
            for word in 0..4 {
                let lo_idx = 2 * word;
                let hi_idx = lo_idx + 1;
                let (lo, hi) = reduce_pair(load(&cv[lo_idx]), load(&cv[hi_idx]));
                cv[lo_idx] = store(lo);
                cv[hi_idx] = store(hi);
            }
            cv
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(target_feature = "avx512f")))]
    mod x86_64_avx2 {
        use core::arch::x86_64::*;

        #[inline(always)]
        fn load(xs: &[u32; 8]) -> __m256i {
            unsafe { _mm256_loadu_si256(xs.as_ptr().cast()) }
        }

        #[inline(always)]
        fn store(x: __m256i) -> [u32; 8] {
            let mut out = [0u32; 8];
            unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), x) };
            out
        }

        #[inline(always)]
        fn reduce_pair(lo: __m256i, hi: __m256i) -> (__m256i, __m256i) {
            unsafe {
                let zero = _mm256_setzero_si256();
                let ones = _mm256_set1_epi32(-1);
                let reduce =
                    _mm256_andnot_si256(_mm256_cmpeq_epi32(lo, zero), _mm256_cmpeq_epi32(hi, ones));
                let lo = _mm256_sub_epi32(lo, _mm256_and_si256(reduce, _mm256_set1_epi32(1)));
                let hi = _mm256_andnot_si256(reduce, hi);
                (lo, hi)
            }
        }

        pub(super) fn finalize_8(mut cv: [[u32; 8]; 8]) -> [[u32; 8]; 8] {
            for word in 0..4 {
                let lo_idx = 2 * word;
                let hi_idx = lo_idx + 1;
                let (lo, hi) = reduce_pair(load(&cv[lo_idx]), load(&cv[hi_idx]));
                cv[lo_idx] = store(lo);
                cv[hi_idx] = store(hi);
            }
            cv
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    mod x86_64_avx512 {
        use core::arch::x86_64::*;

        #[inline(always)]
        fn load(xs: &[u32; 16]) -> __m512i {
            unsafe { _mm512_loadu_si512(xs.as_ptr().cast()) }
        }

        #[inline(always)]
        fn store(x: __m512i) -> [u32; 16] {
            let mut out = [0u32; 16];
            unsafe { _mm512_storeu_si512(out.as_mut_ptr().cast(), x) };
            out
        }

        #[inline(always)]
        fn reduce_pair(lo: __m512i, hi: __m512i) -> (__m512i, __m512i) {
            unsafe {
                let zero = _mm512_setzero_si512();
                let reduce = _mm512_cmpeq_epi32_mask(hi, _mm512_set1_epi32(-1))
                    & !_mm512_cmpeq_epi32_mask(lo, zero);
                let lo = _mm512_mask_sub_epi32(lo, reduce, lo, _mm512_set1_epi32(1));
                let hi = _mm512_mask_mov_epi32(hi, reduce, zero);
                (lo, hi)
            }
        }

        pub(super) fn finalize_16(mut cv: [[u32; 16]; 8]) -> [[u32; 16]; 8] {
            for word in 0..4 {
                let lo_idx = 2 * word;
                let hi_idx = lo_idx + 1;
                let (lo, hi) = reduce_pair(load(&cv[lo_idx]), load(&cv[hi_idx]));
                cv[lo_idx] = store(lo);
                cv[hi_idx] = store(hi);
            }
            cv
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod neon {
        use core::arch::aarch64::*;

        #[inline(always)]
        fn load(xs: &[u32; 4]) -> uint32x4_t {
            unsafe { vld1q_u32(xs.as_ptr()) }
        }

        #[inline(always)]
        fn store(x: uint32x4_t) -> [u32; 4] {
            let mut out = [0u32; 4];
            unsafe { vst1q_u32(out.as_mut_ptr(), x) };
            out
        }

        #[inline(always)]
        fn reduce_pair(lo: uint32x4_t, hi: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
            unsafe {
                let zero = vdupq_n_u32(0);
                let reduce =
                    vandq_u32(vceqq_u32(hi, vdupq_n_u32(u32::MAX)), vmvnq_u32(vceqq_u32(lo, zero)));
                let lo = vsubq_u32(lo, vandq_u32(reduce, vdupq_n_u32(1)));
                let hi = vandq_u32(hi, vmvnq_u32(reduce));
                (lo, hi)
            }
        }

        pub(super) fn finalize_4(mut cv: [[u32; 4]; 8]) -> [[u32; 4]; 8] {
            for word in 0..4 {
                let lo_idx = 2 * word;
                let hi_idx = lo_idx + 1;
                let (lo, hi) = reduce_pair(load(&cv[lo_idx]), load(&cv[hi_idx]));
                cv[lo_idx] = store(lo);
                cv[hi_idx] = store(hi);
            }
            cv
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chaining value used across the BlakeG tests.
    const TEST_CV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0x254f_f53a,
        0x0000_0000,
        0x9b05_688c,
        0x0000_0000,
        0x5be0_cd19,
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
        blake3_schedule::compress_raw_with_parameter_words(cv, block, p)
    }

    fn reference_core_xof_with_p(cv: [u32; 8], block: [u32; 16], p: [u32; 4]) -> [u32; 16] {
        blake3_schedule::compress_raw_xof_with_parameter_words(cv, block, p)
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
        let compressed = standard_blake3_compress(IV, block, 0, 64, CHUNK_START | CHUNK_END | ROOT);

        assert_eq!(words_to_bytes(compressed), *blake3::hash(&bytes).as_bytes());
    }

    #[test]
    fn blakeg_is_blake3_core_with_fixed_iv_tail_and_modular_reduction() {
        let cv = TEST_CV;
        let block = test_block();
        let expected =
            finalize_output(reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]));

        assert_eq!(BlakeG::compress(cv, block), expected);
    }

    #[test]
    fn compress_raw_is_blake3_fold_with_fixed_iv_tail() {
        let cv = TEST_CV;
        let block = test_block();
        let expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        assert_eq!(BlakeG::compress_raw(cv, block), expected);
    }

    #[test]
    fn xof_reference_matches_official_blake3_compress_xof() {
        let cv = TEST_CV;
        let block = test_block();
        let counter = 0x0123_4567_89ab_cdefu64;
        let block_len = 64u8;
        let flags = 0x0bu8;

        let xof_bytes = blake3::platform::Platform::Portable.compress_xof(
            &cv,
            &block_words_to_bytes(block),
            block_len,
            counter,
            flags,
        );
        let official: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(xof_bytes[4 * i..4 * i + 4].try_into().unwrap())
        });
        let reference = reference_core_xof_with_p(
            cv,
            block,
            [counter as u32, (counter >> 32) as u32, block_len as u32, flags as u32],
        );

        assert_eq!(reference, official);
    }

    #[test]
    fn compress_raw_xof_is_blake3_xof_with_fixed_iv_tail() {
        let cv = TEST_CV;
        let block = test_block();
        let xof = BlakeG::compress_raw_xof(cv, block);

        // Low half is identical to the folded raw output.
        assert_eq!(&xof[..8], &BlakeG::compress_raw(cv, block));

        // Full 16 words match the BLAKE3 XOF reference with BlakeG's fixed IV tail.
        let expected = reference_core_xof_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        assert_eq!(xof, expected);
    }

    #[test]
    fn compress_raw_then_reduce_matches_compress() {
        let cv = TEST_CV;
        let block = test_block();

        assert_eq!(finalize_output(BlakeG::compress_raw(cv, block)), BlakeG::compress(cv, block));
    }

    #[test]
    fn reduction_wraps_goldilocks_modulus() {
        assert_eq!(reduce_u32_pair(0, 0), (0, 0));
        assert_eq!(reduce_u32_pair(0, 0xffff_ffff), (0, 0xffff_ffff));
        assert_eq!(reduce_u32_pair(1, 0xffff_ffff), (0, 0));
        assert_eq!(reduce_u32_pair(u32::MAX, u32::MAX), (u32::MAX - 1, 0));
    }

    fn packed_finalizer_edge_input<const LANES: usize>() -> [[u32; LANES]; 8] {
        const CASES: [(u32, u32); 6] = [
            (0, 0),
            (0, u32::MAX),
            (1, u32::MAX),
            (u32::MAX, u32::MAX),
            (17, 0x7fff_ffff),
            (0x8000_0000, 0xffff_fffe),
        ];

        core::array::from_fn(|word| {
            core::array::from_fn(|lane| {
                let (lo, hi) = CASES[(lane + word / 2) % CASES.len()];
                if word % 2 == 0 { lo } else { hi }
            })
        })
    }

    #[test]
    fn packed_finalizer_4_matches_scalar_edges() {
        let cv = packed_finalizer_edge_input::<4>();
        assert_eq!(finalize_packed_output_4(cv), finalize_packed_output_scalar(cv));
    }

    #[test]
    fn native_packed_finalizer_matches_scalar_edges() {
        let cv = packed_finalizer_edge_input::<PACKED_LANES>();
        assert_eq!(finalize_packed_output_native(cv), finalize_packed_output_scalar(cv));
    }

    #[test]
    fn compress_accepts_unmasked_input_cv_lanes() {
        let mut cv = TEST_CV;
        cv[1] |= 0x8000_0000;
        cv[3] |= 0x8000_0000;
        cv[5] |= 0x8000_0000;
        cv[7] |= 0x8000_0000;
        let block = test_block();
        let expected =
            finalize_output(reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]));

        assert_eq!(BlakeG::compress(cv, block), expected);
    }

    #[test]
    fn standard_blake3_compression_is_not_blakeg_mode() {
        let cv = TEST_CV;
        let block = test_block();
        let standard = finalize_output(standard_blake3_compress(cv, block, 0, 64, 0));

        assert_ne!(BlakeG::compress(cv, block), standard);
    }

    #[test]
    fn compress_output_lanes_encode_canonical_felts() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32 + 1);
        let cv_new = BlakeG::compress(TEST_CV, block);

        for word in 0..4 {
            let value = ((cv_new[2 * word + 1] as u64) << 32) | cv_new[2 * word] as u64;
            assert!(value < Felt::ORDER, "cv_new pair {word} must be canonical");
        }
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

    #[test]
    fn compress_packed_4_matches_scalar_lanes() {
        const LANES: usize = 4;

        let cvs: [[u32; 8]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| TEST_CV[i].wrapping_add((lane as u32) << (i % 7)))
        });
        let blocks: [[u32; 16]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| {
                0x1020_3040u32
                    .wrapping_add((lane as u32).wrapping_mul(0x1111_1111))
                    .wrapping_add((i as u32).wrapping_mul(0x0102_0304))
            })
        });

        let packed_cv: [[u32; LANES]; 8] =
            core::array::from_fn(|word| core::array::from_fn(|lane| cvs[lane][word]));
        let packed_block: [[u32; LANES]; 16] =
            core::array::from_fn(|word| core::array::from_fn(|lane| blocks[lane][word]));
        let packed_out = BlakeG::compress_packed(packed_cv, packed_block);
        let packed_out_4 = BlakeG::compress_packed_4(packed_cv, packed_block);
        #[cfg(feature = "internal")]
        let packed_out_4_shift = BlakeG::compress_packed_4_rotr8_shift(packed_cv, packed_block);
        #[cfg(feature = "internal")]
        let packed_out_4_cached = BlakeG::compress_packed_4_rotr8_cached(packed_cv, packed_block);
        #[cfg(feature = "internal")]
        let packed_out_4_preloaded =
            BlakeG::compress_packed_4_preloaded_messages(packed_cv, packed_block);

        for lane in 0..LANES {
            let scalar = BlakeG::compress(cvs[lane], blocks[lane]);
            let packed_lane: [u32; 8] = core::array::from_fn(|word| packed_out[word][lane]);
            let packed_lane_4: [u32; 8] = core::array::from_fn(|word| packed_out_4[word][lane]);
            assert_eq!(packed_lane, scalar);
            assert_eq!(packed_lane_4, scalar);
            #[cfg(feature = "internal")]
            {
                let shift_lane: [u32; 8] =
                    core::array::from_fn(|word| packed_out_4_shift[word][lane]);
                let cached_lane: [u32; 8] =
                    core::array::from_fn(|word| packed_out_4_cached[word][lane]);
                let preloaded_lane: [u32; 8] =
                    core::array::from_fn(|word| packed_out_4_preloaded[word][lane]);
                assert_eq!(shift_lane, scalar);
                assert_eq!(cached_lane, scalar);
                assert_eq!(preloaded_lane, scalar);
            }
        }
    }

    #[test]
    fn compress_packed_native_matches_scalar_lanes() {
        const LANES: usize = PACKED_LANES;

        let cvs: [[u32; 8]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| TEST_CV[i].wrapping_add((lane as u32) << (i % 7)))
        });
        let blocks: [[u32; 16]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| {
                0x1020_3040u32
                    .wrapping_add((lane as u32).wrapping_mul(0x1111_1111))
                    .wrapping_add((i as u32).wrapping_mul(0x0102_0304))
            })
        });

        let packed_cv: [[u32; LANES]; 8] =
            core::array::from_fn(|word| core::array::from_fn(|lane| cvs[lane][word]));
        let packed_block: [[u32; LANES]; 16] =
            core::array::from_fn(|word| core::array::from_fn(|lane| blocks[lane][word]));
        let portable = BlakeG::compress_packed(packed_cv, packed_block);
        let native = BlakeG::compress_packed_native(packed_cv, packed_block);

        for lane in 0..LANES {
            let scalar = BlakeG::compress(cvs[lane], blocks[lane]);
            let portable_lane: [u32; 8] = core::array::from_fn(|word| portable[word][lane]);
            let native_lane: [u32; 8] = core::array::from_fn(|word| native[word][lane]);
            assert_eq!(portable_lane, scalar);
            assert_eq!(native_lane, scalar);
        }
    }
}
