//! Goldilocks-tailored BLAKE3 compression.
//!
//! BlakeG uses BLAKE3's 7-round compression core with fixed parameter words.
//! `compress` maps the 16-word raw XOF fold to four Goldilocks field elements
//! with a fixed linear finalizer.

mod blake3_schedule;

#[cfg(test)]
pub(super) const IV: [u32; 8] = blake3_schedule::IV;
pub(super) const PACKED_LANES: usize = blake3_schedule::PACKED_LANES;

const GOLDILOCKS_EPSILON: u64 = 0xffff_ffff;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

const FINALIZER_MATRIX: [[u64; 16]; 4] = [
    [
        15904662775280568261,
        11248103468244892543,
        9896915777956725816,
        185045353106015793,
        8500216796624591099,
        8360920247338155255,
        10180691449194265163,
        9837003373551522125,
        17467273734926731113,
        2417479524490811079,
        11233314090082918225,
        2233533576056214764,
        17209626757598516148,
        1311325837214623087,
        17541990409531268444,
        8778650702833371576,
    ],
    [
        10351818539131852076,
        16011254545682850612,
        17088821416796162493,
        288129510519252377,
        13610881561350213016,
        3540193630759490816,
        6810056141036989685,
        2582601007098108630,
        12095802721559781052,
        4693227732633196995,
        7475118991187684203,
        3613121121392294874,
        4075547714329698345,
        133921402081467462,
        2232830006922210412,
        9983172029845936448,
    ],
    [
        43492802588642506,
        3224823005913593020,
        16350268760635732189,
        3235941269094163408,
        12211684808931190196,
        11036966493196891711,
        18142572304476028282,
        8994326269973484641,
        13283425880831860268,
        858512574931661773,
        2994039940363751996,
        1639666242891561583,
        10544831527494131096,
        5657627761754840060,
        8399352252962716189,
        7729055846046801067,
    ],
    [
        5791738195767590909,
        8616178313052031618,
        9917353469636318118,
        5622607317059886827,
        9180561841259757438,
        8570780836823824523,
        10644109930340636559,
        5023452280734745604,
        16936908147648204300,
        13390427418905232145,
        167198939826968494,
        14327318216038165875,
        5175145684803592810,
        1063676696373794935,
        7285040222901297781,
        9407507053369299131,
    ],
];

#[inline(always)]
fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hh = hi >> 32;
    let hl = hi & 0xffff_ffff;

    let (mut t0, borrow) = lo.overflowing_sub(hh);
    if borrow {
        t0 = t0.wrapping_sub(GOLDILOCKS_EPSILON);
    }

    let t1 = (hl << 32).wrapping_sub(hl);
    let (mut r, carry) = t0.overflowing_add(t1);
    if carry {
        r = r.wrapping_add(GOLDILOCKS_EPSILON);
    }
    if r >= GOLDILOCKS_MODULUS {
        r = r.wrapping_sub(GOLDILOCKS_MODULUS);
    }
    r
}

#[inline(always)]
fn matrix_finalize_to_cv(input: &[u32; 16]) -> [u32; 8] {
    let mut acc = [0u128; 4];
    for (i, &word) in input.iter().enumerate() {
        let x = word as u128;
        acc[0] += (FINALIZER_MATRIX[0][i] as u128) * x;
        acc[1] += (FINALIZER_MATRIX[1][i] as u128) * x;
        acc[2] += (FINALIZER_MATRIX[2][i] as u128) * x;
        acc[3] += (FINALIZER_MATRIX[3][i] as u128) * x;
    }

    let values = acc.map(reduce128);
    core::array::from_fn(|i| {
        let value = values[i / 2];
        if i % 2 == 0 { value as u32 } else { (value >> 32) as u32 }
    })
}

#[inline(always)]
#[cfg(any(test, not(target_arch = "aarch64")))]
fn matrix_finalize_packed_to_cv<const LANES: usize>(
    input: &[[u32; LANES]; 16],
) -> [[u32; LANES]; 8] {
    let mut acc = [[0u128; LANES]; 4];
    for (i, words) in input.iter().enumerate() {
        for (lane, &word) in words.iter().enumerate() {
            let x = word as u128;
            acc[0][lane] += (FINALIZER_MATRIX[0][i] as u128) * x;
            acc[1][lane] += (FINALIZER_MATRIX[1][i] as u128) * x;
            acc[2][lane] += (FINALIZER_MATRIX[2][i] as u128) * x;
            acc[3][lane] += (FINALIZER_MATRIX[3][i] as u128) * x;
        }
    }

    let values: [[u64; LANES]; 4] =
        core::array::from_fn(|row| core::array::from_fn(|lane| reduce128(acc[row][lane])));
    core::array::from_fn(|word| {
        core::array::from_fn(|lane| {
            let value = values[word / 2][lane];
            if word % 2 == 0 {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

#[inline(always)]
fn matrix_finalize_packed_native_to_cv(
    input: &[[u32; PACKED_LANES]; 16],
) -> [[u32; PACKED_LANES]; 8] {
    #[cfg(target_arch = "aarch64")]
    {
        return neon::matrix_finalize_packed_4(input);
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        matrix_finalize_packed_to_cv(input)
    }
}

/// Goldilocks-tailored BLAKE3 compression.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct BlakeG;

impl BlakeG {
    /// Applies BlakeG and returns four canonical Goldilocks elements as low/high
    /// `u32` limbs.
    ///
    /// The input chaining value may contain arbitrary `u32` lanes. The
    /// Goldilocks finalizer is an output rule, not an input invariant.
    pub(super) fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        matrix_finalize_to_cv(&Self::compress_raw_xof(cv, block))
    }

    /// Apply BlakeG's raw compression core.
    ///
    /// Returns the eight folded BLAKE3/BlakeG output words:
    ///
    /// ```text
    /// out[i] = v[i] ^ v[i + 8]
    /// ```
    ///
    /// This is a raw compression output, not an Eidos digest. Callers that use
    /// BlakeG as a hash must bind domain, mode, and length into the input CV.
    pub fn compress_raw(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        blake3_schedule::compress_raw(cv, block)
    }

    /// Apply BlakeG and return the full 16-word XOF output (low half || high
    /// half), before the Goldilocks matrix finalizer.
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
        matrix_finalize_packed_to_cv(&blake3_schedule::compress_packed_raw_xof(cv, block))
    }

    /// Apply BlakeG to four independent lanes.
    ///
    /// On `aarch64`, this uses NEON. On `x86_64`, this uses SSE2. Other targets
    /// fall back to the portable packed implementation.
    #[cfg(test)]
    #[inline]
    pub(super) fn compress_packed_4(cv: [[u32; 4]; 8], block: [[u32; 4]; 16]) -> [[u32; 4]; 8] {
        matrix_finalize_packed_to_cv(&blake3_schedule::compress_packed_4_raw_xof(cv, block))
    }

    /// Apply BlakeG to the build's selected native packed lane width.
    #[inline]
    pub(super) fn compress_packed_native(
        cv: [[u32; PACKED_LANES]; 8],
        block: [[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        matrix_finalize_packed_native_to_cv(&blake3_schedule::compress_packed_native_raw_xof(
            cv, block,
        ))
    }

    #[cfg(test)]
    pub(super) fn compress_packed_4_rotr8_shift(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        matrix_finalize_packed_to_cv(&blake3_schedule::compress_packed_4_rotr8_shift_raw_xof(
            cv, block,
        ))
    }

    #[cfg(test)]
    pub(super) fn compress_packed_4_rotr8_cached(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        matrix_finalize_packed_to_cv(&blake3_schedule::compress_packed_4_rotr8_cached_raw_xof(
            cv, block,
        ))
    }

    #[cfg(test)]
    pub(super) fn compress_packed_4_preloaded_messages(
        cv: [[u32; 4]; 8],
        block: [[u32; 4]; 16],
    ) -> [[u32; 4]; 8] {
        matrix_finalize_packed_to_cv(
            &blake3_schedule::compress_packed_4_preloaded_messages_raw_xof(cv, block),
        )
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::{FINALIZER_MATRIX, GOLDILOCKS_EPSILON, GOLDILOCKS_MODULUS};

    #[inline(always)]
    fn reduce128_branchless(x: u128) -> u64 {
        let lo = x as u64;
        let hi = (x >> 64) as u64;
        let hh = hi >> 32;
        let hl = hi & 0xffff_ffff;

        let (t0, borrow) = lo.overflowing_sub(hh);
        let t0 = t0.wrapping_sub((borrow as u64).wrapping_mul(GOLDILOCKS_EPSILON));

        let t1 = (hl << 32).wrapping_sub(hl);
        let (r, carry) = t0.overflowing_add(t1);
        let r = r.wrapping_add((carry as u64).wrapping_mul(GOLDILOCKS_EPSILON));
        if r >= GOLDILOCKS_MODULUS {
            r.wrapping_sub(GOLDILOCKS_MODULUS)
        } else {
            r
        }
    }

    fn matrix_finalize_rows_pair<const ROW0: usize, const ROW1: usize>(
        input: &[[u32; 4]; 16],
    ) -> ([u32; 4], [u32; 4], [u32; 4], [u32; 4]) {
        let mut acc00 = 0u128;
        let mut acc01 = 0u128;
        let mut acc02 = 0u128;
        let mut acc03 = 0u128;
        let mut acc10 = 0u128;
        let mut acc11 = 0u128;
        let mut acc12 = 0u128;
        let mut acc13 = 0u128;

        macro_rules! absorb {
            ($i:literal) => {{
                let coeff0 = FINALIZER_MATRIX[ROW0][$i] as u128;
                let coeff1 = FINALIZER_MATRIX[ROW1][$i] as u128;
                let word = input[$i];
                let x0 = word[0] as u128;
                let x1 = word[1] as u128;
                let x2 = word[2] as u128;
                let x3 = word[3] as u128;

                acc00 += coeff0 * x0;
                acc01 += coeff0 * x1;
                acc02 += coeff0 * x2;
                acc03 += coeff0 * x3;

                acc10 += coeff1 * x0;
                acc11 += coeff1 * x1;
                acc12 += coeff1 * x2;
                acc13 += coeff1 * x3;
            }};
        }

        absorb!(0);
        absorb!(1);
        absorb!(2);
        absorb!(3);
        absorb!(4);
        absorb!(5);
        absorb!(6);
        absorb!(7);
        absorb!(8);
        absorb!(9);
        absorb!(10);
        absorb!(11);
        absorb!(12);
        absorb!(13);
        absorb!(14);
        absorb!(15);

        let value00 = reduce128_branchless(acc00);
        let value01 = reduce128_branchless(acc01);
        let value02 = reduce128_branchless(acc02);
        let value03 = reduce128_branchless(acc03);
        let value10 = reduce128_branchless(acc10);
        let value11 = reduce128_branchless(acc11);
        let value12 = reduce128_branchless(acc12);
        let value13 = reduce128_branchless(acc13);

        (
            [value00 as u32, value01 as u32, value02 as u32, value03 as u32],
            [
                (value00 >> 32) as u32,
                (value01 >> 32) as u32,
                (value02 >> 32) as u32,
                (value03 >> 32) as u32,
            ],
            [value10 as u32, value11 as u32, value12 as u32, value13 as u32],
            [
                (value10 >> 32) as u32,
                (value11 >> 32) as u32,
                (value12 >> 32) as u32,
                (value13 >> 32) as u32,
            ],
        )
    }

    #[inline(always)]
    fn matrix_finalize_rows_to_cv(input: &[[u32; 4]; 16]) -> [[u32; 4]; 8] {
        let (out0, out1, out2, out3) = matrix_finalize_rows_pair::<0, 1>(input);
        let (out4, out5, out6, out7) = matrix_finalize_rows_pair::<2, 3>(input);

        [out0, out1, out2, out3, out4, out5, out6, out7]
    }

    #[inline(never)]
    pub(super) fn matrix_finalize_packed_4(input: &[[u32; 4]; 16]) -> [[u32; 4]; 8] {
        matrix_finalize_rows_to_cv(input)
    }
}

#[cfg(feature = "internal")]
#[doc(hidden)]
pub mod bench {
    use super::{
        BlakeG, PACKED_LANES, blake3_schedule, matrix_finalize_packed_native_to_cv,
        matrix_finalize_to_cv,
    };

    pub const NATIVE_LANES: usize = PACKED_LANES;

    #[inline]
    pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        BlakeG::compress(cv, block)
    }

    #[inline]
    pub fn compress_raw_xof(cv: [u32; 8], block: [u32; 16]) -> [u32; 16] {
        BlakeG::compress_raw_xof(cv, block)
    }

    #[inline]
    pub fn matrix_finalize(input: [u32; 16]) -> [u32; 8] {
        matrix_finalize_to_cv(&input)
    }

    #[inline]
    pub fn compress_packed_native(
        cv: [[u32; NATIVE_LANES]; 8],
        block: [[u32; NATIVE_LANES]; 16],
    ) -> [[u32; NATIVE_LANES]; 8] {
        BlakeG::compress_packed_native(cv, block)
    }

    #[inline]
    pub fn compress_packed_native_raw_xof(
        cv: [[u32; NATIVE_LANES]; 8],
        block: [[u32; NATIVE_LANES]; 16],
    ) -> [[u32; NATIVE_LANES]; 16] {
        blake3_schedule::compress_packed_native_raw_xof(cv, block)
    }

    #[inline]
    pub fn matrix_finalize_packed_native(
        input: [[u32; NATIVE_LANES]; 16],
    ) -> [[u32; NATIVE_LANES]; 8] {
        matrix_finalize_packed_native_to_cv(&input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Init-style chaining value used across the BlakeG tests.
    const TEST_CV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
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

    fn matrix_finalize_reference(input: &[u32; 16]) -> [u32; 8] {
        let values: [u64; 4] = core::array::from_fn(|row| {
            let acc = input.iter().enumerate().fold(0u128, |acc, (i, &word)| {
                acc + (FINALIZER_MATRIX[row][i] as u128) * (word as u128)
            });
            (acc % (GOLDILOCKS_MODULUS as u128)) as u64
        });

        core::array::from_fn(|i| {
            let value = values[i / 2];
            if i % 2 == 0 { value as u32 } else { (value >> 32) as u32 }
        })
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
    fn reduce128_matches_direct_modulo_on_edges() {
        const MODULUS: u128 = GOLDILOCKS_MODULUS as u128;
        const MAX_MATRIX_ACC: u128 = 16 * (u64::MAX as u128) * (u32::MAX as u128);

        for x in [
            0,
            1,
            MODULUS - 1,
            MODULUS,
            MODULUS + 1,
            u64::MAX as u128,
            1u128 << 64,
            (1u128 << 64) + (1u128 << 32),
            MAX_MATRIX_ACC,
            u128::MAX,
        ] {
            assert_eq!(reduce128(x), (x % MODULUS) as u64);
        }
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
    fn blakeg_is_blake3_core_with_fixed_iv_tail_and_matrix_finalizer() {
        let cv = TEST_CV;
        let block = test_block();
        let wide = reference_core_xof_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        let expected = matrix_finalize_reference(&wide);

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
    fn compress_raw_xof_then_matrix_matches_compress() {
        let cv = TEST_CV;
        let block = test_block();
        let raw_xof = BlakeG::compress_raw_xof(cv, block);

        assert_eq!(matrix_finalize_to_cv(&raw_xof), BlakeG::compress(cv, block));
    }

    #[test]
    fn matrix_finalizer_matches_direct_modulo_on_edge_inputs() {
        let inputs = [
            [0u32; 16],
            [u32::MAX; 16],
            core::array::from_fn(|i| if i % 2 == 0 { 0 } else { u32::MAX }),
            core::array::from_fn(|i| 0x0102_0304u32.wrapping_mul(i as u32 + 1)),
            reference_core_xof_with_p(TEST_CV, test_block(), [IV[4], IV[5], IV[6], IV[7]]),
        ];

        for input in inputs {
            assert_eq!(matrix_finalize_to_cv(&input), matrix_finalize_reference(&input));
        }
    }

    #[test]
    fn compress_accepts_unmasked_input_cv_lanes() {
        let mut cv = TEST_CV;
        cv[1] |= 0x8000_0000;
        cv[3] |= 0x8000_0000;
        cv[5] |= 0x8000_0000;
        cv[7] |= 0x8000_0000;
        let block = test_block();
        let wide = reference_core_xof_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        let expected = matrix_finalize_reference(&wide);

        assert_eq!(BlakeG::compress(cv, block), expected);
    }

    #[test]
    fn standard_blake3_compression_is_not_blakeg_mode() {
        let cv = TEST_CV;
        let block = test_block();
        let standard = standard_blake3_compress(cv, block, 0, 64, 0);

        assert_ne!(BlakeG::compress(cv, block), standard);
    }

    #[test]
    fn compress_output_lanes_encode_canonical_felts() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32 + 1);
        let cv_new = BlakeG::compress(TEST_CV, block);

        for word in 0..4 {
            let value = ((cv_new[2 * word + 1] as u64) << 32) | cv_new[2 * word] as u64;
            assert!(value < GOLDILOCKS_MODULUS);
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
        let packed_out_4_shift = BlakeG::compress_packed_4_rotr8_shift(packed_cv, packed_block);
        let packed_out_4_cached = BlakeG::compress_packed_4_rotr8_cached(packed_cv, packed_block);
        let packed_out_4_preloaded =
            BlakeG::compress_packed_4_preloaded_messages(packed_cv, packed_block);

        for lane in 0..LANES {
            let scalar = BlakeG::compress(cvs[lane], blocks[lane]);
            let packed_lane: [u32; 8] = core::array::from_fn(|word| packed_out[word][lane]);
            let packed_lane_4: [u32; 8] = core::array::from_fn(|word| packed_out_4[word][lane]);
            assert_eq!(packed_lane, scalar);
            assert_eq!(packed_lane_4, scalar);
            let shift_lane: [u32; 8] = core::array::from_fn(|word| packed_out_4_shift[word][lane]);
            let cached_lane: [u32; 8] =
                core::array::from_fn(|word| packed_out_4_cached[word][lane]);
            let preloaded_lane: [u32; 8] =
                core::array::from_fn(|word| packed_out_4_preloaded[word][lane]);
            assert_eq!(shift_lane, scalar);
            assert_eq!(cached_lane, scalar);
            assert_eq!(preloaded_lane, scalar);
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
