//! WASM32 simd128 packed `Felt`. WIDTH = 2 (one v128 register holds two
//! Goldilocks elements as i64x2 lanes).
//!
//! Self-contained — uses `core::arch::wasm32` intrinsics directly. We do
//! NOT depend on a Plonky3-provided packed Goldilocks type (Plonky3 0.5.2
//! does not ship one for wasm32+simd128). The arithmetic recipes are the
//! standard Goldilocks SIMD recipes, modeled on Plonky3's existing
//! `aarch64_neon` and `x86_64_avx2` backends with intrinsic renaming:
//!
//!   uint64x2_t                 → v128
//!   veorq_u64(a, b)            → v128_xor(a, b)
//!   vaddq_u64(a, b)            → i64x2_add(a, b)
//!   vsubq_u64(a, b)            → i64x2_sub(a, b)
//!   vcgtq_s64(a, b)            → i64x2_gt(a, b)
//!   vbicq_u64(a, b)            → v128_andnot(a, b)  (= a & !b)
//!   vshrq_n_u64::<32>(a)       → u64x2_shr(a, 32)
//!   vdupq_n_u64(x)             → u64x2_splat(x)
//!   vreinterpretq_s64_u64(x)   → identity (v128 is type-erased)
//!
//! Felt is `#[repr(transparent)]` over Goldilocks, which is
//! `#[repr(transparent)]` over u64. So `[Felt; 2]` shares its byte layout
//! with `[u64; 2]` and with `v128`, which lets us `transmute` freely
//! between the three.

use alloc::vec::Vec;
use core::arch::wasm32::{
    i32x4_shuffle, i64x2_add, i64x2_extmul_low_u32x4, i64x2_gt, i64x2_shl, i64x2_shuffle,
    i64x2_sub, u64x2_shr, u64x2_splat, v128, v128_and, v128_andnot, v128_or, v128_xor,
};
use core::iter::{Product, Sum};
use core::mem::transmute;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use p3_field::exponentiation::exp_10540996611094048183;
use p3_field::op_assign_macros::{
    impl_add_assign, impl_add_base_field, impl_div_methods, impl_mul_base_field, impl_mul_methods,
    impl_packed_value, impl_rng, impl_sub_assign, impl_sub_base_field, impl_sum_prod_base_field,
    ring_sum,
};
use p3_field::{
    Algebra, Field, InjectiveMonomial, PackedField, PackedFieldPow2, PackedValue,
    PermutationMonomial, PrimeCharacteristicRing,
};
use rand::distr::{Distribution, StandardUniform};
use rand::{Rng, RngExt};

use super::super::Felt;

pub const WIDTH: usize = 2;

/// Equal to `2^32 - 1 = 2^64 mod P`.
const EPSILON: u64 = Felt::ORDER.wrapping_neg();

// Compile-time guard: PackedFelt is only sound to transmute to/from v128 if
// its byte layout matches. `[Felt; 2]` === `[u64; 2]` === `v128` (16 bytes
// total). Note that the `to_vector` / `from_vector` helpers below are
// VALUE transmutes (`transmute(self) -> v128`), not reference reinterprets,
// so alignment is irrelevant for them — the compiler allocates space for
// the result type with whatever alignment that type requires. Only the
// const v128 initializers (`SIGN_BIT`, `SHIFTED_FIELD_ORDER`, `EPSILON_VEC`
// below) and the underlying byte-equivalence chain matter.
const _LAYOUT_INVARIANTS: () = {
    assert!(size_of::<[Felt; WIDTH]>() == size_of::<v128>());
    assert!(size_of::<Felt>() == size_of::<u64>());
};

/// Vectorized wasm32-simd128 packed `Felt`.
///
/// `repr(transparent)` over `[Felt; WIDTH]` so we can `transmute` freely
/// between `[Felt; 2]`, `[u64; 2]`, and `v128`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
#[must_use]
pub struct PackedFelt(pub [Felt; WIDTH]);

impl PackedFelt {
    #[inline]
    fn to_vector(self) -> v128 {
        // SAFETY: see _LAYOUT_INVARIANTS — byte layout matches.
        unsafe { transmute(self) }
    }

    #[inline]
    fn from_vector(vector: v128) -> Self {
        // SAFETY: see _LAYOUT_INVARIANTS — byte layout matches.
        unsafe { transmute(vector) }
    }

    #[inline]
    pub const fn broadcast(value: Felt) -> Self {
        Self([value; WIDTH])
    }

    #[inline]
    pub const fn as_array(&self) -> &[Felt; WIDTH] {
        &self.0
    }
}

impl From<Felt> for PackedFelt {
    fn from(x: Felt) -> Self {
        Self::broadcast(x)
    }
}

// ============================================================================
// Constants used by the shifted-representation arithmetic.
// ============================================================================

const SIGN_BIT: v128 =
    unsafe { transmute::<[u64; 2], v128>([0x8000_0000_0000_0000u64; WIDTH]) };
const SHIFTED_FIELD_ORDER: v128 = unsafe {
    transmute::<[u64; 2], v128>([Felt::ORDER ^ 0x8000_0000_0000_0000u64; WIDTH])
};
const EPSILON_VEC: v128 = unsafe { transmute::<[u64; 2], v128>([EPSILON; WIDTH]) };

#[inline(always)]
fn shift(x: v128) -> v128 {
    v128_xor(x, SIGN_BIT)
}

/// If `x_s < SHIFTED_FIELD_ORDER` (signed comparison), add EPSILON to
/// canonicalize. The neon impl uses `vbicq_u64(EPSILON_VEC, mask)` =
/// `EPSILON_VEC & !mask`. wasm32's `v128_andnot(a, b) = a & !b` matches.
#[inline(always)]
fn canonicalize_s(x_s: v128) -> v128 {
    let mask = i64x2_gt(SHIFTED_FIELD_ORDER, x_s);
    let wrapback_amt = v128_andnot(EPSILON_VEC, mask);
    i64x2_add(x_s, wrapback_amt)
}

#[inline(always)]
fn add_no_double_overflow_64_64s_s(x: v128, y_s: v128) -> v128 {
    let res_wrapped_s = i64x2_add(x, y_s);
    // Overflow detected: y_s > res_wrapped_s (signed). On overflow, add EPSILON.
    let mask = i64x2_gt(y_s, res_wrapped_s);
    let wrapback_amt = u64x2_shr(mask, 32);
    i64x2_add(res_wrapped_s, wrapback_amt)
}

/// Goldilocks modular addition.
#[inline]
fn add(x: v128, y: v128) -> v128 {
    let y_s = shift(y);
    let res_s = add_no_double_overflow_64_64s_s(x, canonicalize_s(y_s));
    shift(res_s)
}

/// Goldilocks modular subtraction.
#[inline]
fn sub(x: v128, y: v128) -> v128 {
    let y_s = canonicalize_s(shift(y));
    let x_s = shift(x);
    let mask = i64x2_gt(y_s, x_s);
    let wrapback_amt = u64x2_shr(mask, 32);
    let res_wrapped = i64x2_sub(x_s, y_s);
    i64x2_sub(res_wrapped, wrapback_amt)
}

/// Goldilocks modular negation.
#[inline]
fn neg(y: v128) -> v128 {
    let y_s = shift(y);
    i64x2_sub(SHIFTED_FIELD_ORDER, canonicalize_s(y_s))
}

// ============================================================================
// Multiplication: schoolbook 64×64 → 128 + Goldilocks reduction.
// ============================================================================

/// Pack the low 32 bits of each u64 lane into u32 lanes 0 and 1.
/// Input  u32x4 view: [a0_lo, a0_hi, a1_lo, a1_hi]
/// Output u32x4 view: [a0_lo, a1_lo,    *,     *]
#[inline(always)]
fn lo32(a: v128) -> v128 {
    i32x4_shuffle::<0, 2, 0, 0>(a, a)
}

/// Pack the high 32 bits of each u64 lane into u32 lanes 0 and 1.
/// Input  u32x4 view: [a0_lo, a0_hi, a1_lo, a1_hi]
/// Output u32x4 view: [a0_hi, a1_hi,    *,     *]
#[inline(always)]
fn hi32(a: v128) -> v128 {
    i32x4_shuffle::<1, 3, 0, 0>(a, a)
}

/// 32×32 → 64-bit unsigned multiply, lane-aligned.
#[inline(always)]
fn mul_u32_lanes(a_packed: v128, b_packed: v128) -> v128 {
    i64x2_extmul_low_u32x4(a_packed, b_packed)
}

/// Full 64×64 → 128 multiply per lane. Returns `(hi, lo)` where the
/// 128-bit product per lane = `lo + hi * 2^64`. Translation of the AVX2
/// `mul64_64`.
#[inline]
fn mul64_64(x: v128, y: v128) -> (v128, v128) {
    let x_lo = lo32(x);
    let x_hi = hi32(x);
    let y_lo = lo32(y);
    let y_hi = hi32(y);

    // Four pairwise 32×32 → 64 products.
    let ll = mul_u32_lanes(x_lo, y_lo); // x_lo * y_lo
    let lh = mul_u32_lanes(x_lo, y_hi); // x_lo * y_hi
    let hl = mul_u32_lanes(x_hi, y_lo);
    let hh = mul_u32_lanes(x_hi, y_hi);

    // Bignum addition (AVX2 algorithm verbatim):
    //   t0 = hl + (ll >> 32)              (no overflow: ≤ (2^32-1)^2 + (2^32-1) < 2^64)
    //   t1 = lh + (t0 & 0xFFFFFFFF)       (no overflow)
    //   t2 = hh + (t0 >> 32)              (no overflow)
    //   res_hi = t2 + (t1 >> 32)          (no overflow)
    //   res_lo = (ll & 0xFFFFFFFF) | ((t1 & 0xFFFFFFFF) << 32)
    let ll_hi = u64x2_shr(ll, 32);
    let t0 = i64x2_add(hl, ll_hi);
    let t0_lo = v128_and(t0, EPSILON_VEC);
    let t0_hi = u64x2_shr(t0, 32);
    let t1 = i64x2_add(lh, t0_lo);
    let t2 = i64x2_add(hh, t0_hi);
    let t1_hi = u64x2_shr(t1, 32);
    let res_hi = i64x2_add(t2, t1_hi);

    let ll_lo32 = v128_and(ll, EPSILON_VEC);
    let t1_lo32 = v128_and(t1, EPSILON_VEC);
    let t1_shifted = i64x2_shl(t1_lo32, 32);
    let res_lo = v128_or(ll_lo32, t1_shifted);

    (res_hi, res_lo)
}

/// Add a "small" pre-shifted Goldilocks lane. Mirror of AVX2
/// `add_small_64s_64_s`. Uses `i64x2_gt` directly for the overflow mask
/// since wasm32 simd128's `i32x4_*` ops on 64-bit lanes would compare
/// half-lanes.
#[inline(always)]
fn add_small_64s_64_s(x_s: v128, y: v128) -> v128 {
    let res_wrapped_s = i64x2_add(x_s, y);
    let mask = i64x2_gt(x_s, res_wrapped_s); // -1 if overflow
    let wrapback_amt = u64x2_shr(mask, 32); // 0xFFFFFFFF if overflow else 0
    i64x2_add(res_wrapped_s, wrapback_amt)
}

/// Subtract a "small" Goldilocks value. Mirror of `add_small_64s_64_s`.
#[inline(always)]
fn sub_small_64s_64_s(x_s: v128, y: v128) -> v128 {
    let res_wrapped_s = i64x2_sub(x_s, y);
    let mask = i64x2_gt(res_wrapped_s, x_s); // -1 if underflow
    let wrapback_amt = u64x2_shr(mask, 32);
    i64x2_sub(res_wrapped_s, wrapback_amt)
}

/// Reduce a 128-bit value `(hi, lo)` modulo Goldilocks order. Result fits
/// in 64 bits but may be ≥ FIELD_ORDER (subsequent canonicalize handles
/// that on demand). Translation of the AVX2 `reduce128`.
///
/// Uses `2^64 ≡ 2^32 - 1 (mod p)` and `2^96 ≡ -1 (mod p)`.
#[inline]
fn reduce128(hi: v128, lo: v128) -> v128 {
    let lo_s = shift(lo);
    // 2^96 ≡ -1, so the contribution of `hi_hi * 2^96` is `-hi_hi`.
    let hi_hi = u64x2_shr(hi, 32);
    let lo1_s = sub_small_64s_64_s(lo_s, hi_hi);

    // hi_lo32 * EPSILON  where EPSILON = 2^32 - 1.
    // Computed as (hi_lo32 << 32) - hi_lo32, avoiding a full multiply.
    // hi_lo32 ≤ 2^32 - 1, so (hi_lo32 << 32) ≤ 2^64 - 2^32, no overflow.
    let hi_lo32 = v128_and(hi, EPSILON_VEC);
    let hi_lo32_shifted = i64x2_shl(hi_lo32, 32);
    let t1 = i64x2_sub(hi_lo32_shifted, hi_lo32);

    // Result is at most (2^32 - 1)^2 < 2^64, so add_small_64s_64_s applies.
    let lo2_s = add_small_64s_64_s(lo1_s, t1);
    shift(lo2_s)
}

/// Goldilocks modular multiplication.
#[inline]
fn mul(x: v128, y: v128) -> v128 {
    let (hi, lo) = mul64_64(x, y);
    reduce128(hi, lo)
}

// ============================================================================
// Operator trait impls (delegate to the lane-level functions).
// ============================================================================

impl Add for PackedFelt {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::from_vector(add(self.to_vector(), rhs.to_vector()))
    }
}

impl Sub for PackedFelt {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::from_vector(sub(self.to_vector(), rhs.to_vector()))
    }
}

impl Neg for PackedFelt {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self::from_vector(neg(self.to_vector()))
    }
}

impl Mul for PackedFelt {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::from_vector(mul(self.to_vector(), rhs.to_vector()))
    }
}

impl_add_assign!(PackedFelt);
impl_sub_assign!(PackedFelt);
impl_mul_methods!(PackedFelt);
ring_sum!(PackedFelt);
impl_rng!(PackedFelt);

// ============================================================================
// PrimeCharacteristicRing + monomial impls.
// ============================================================================

#[inline(always)]
fn halve(input: v128) -> v128 {
    let one = u64x2_splat(1);
    let zero = u64x2_splat(0);
    let half_v = u64x2_splat(Felt::ORDER.div_ceil(2));
    let least_bit = v128_and(input, one);
    let t = u64x2_shr(input, 1);
    // neg_least_bit = 0 or -1 (broadcast least_bit to all bits within each lane).
    let neg_least_bit = i64x2_sub(zero, least_bit);
    let maybe_half = v128_and(half_v, neg_least_bit);
    i64x2_add(t, maybe_half)
}

#[inline(always)]
fn square(x: v128) -> v128 {
    // No specialized squaring path on simd128; fall through to mul.
    mul(x, x)
}

impl PrimeCharacteristicRing for PackedFelt {
    type PrimeSubfield = <Felt as PrimeCharacteristicRing>::PrimeSubfield;

    const ZERO: Self = Self::broadcast(Felt::ZERO);
    const ONE: Self = Self::broadcast(Felt::ONE);
    const TWO: Self = Self::broadcast(<Felt as PrimeCharacteristicRing>::TWO);
    const NEG_ONE: Self = Self::broadcast(<Felt as PrimeCharacteristicRing>::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::broadcast(<Felt as PrimeCharacteristicRing>::from_prime_subfield(f))
    }

    #[inline]
    fn halve(&self) -> Self {
        Self::from_vector(halve(self.to_vector()))
    }

    #[inline]
    fn square(&self) -> Self {
        Self::from_vector(square(self.to_vector()))
    }

    #[inline]
    fn zero_vec(len: usize) -> Vec<Self> {
        // Straightforward; doesn't reuse the underlying base allocation, but
        // pulling in `p3_util::reconstitute_from_base` to do so adds a dep
        // for marginal allocator gain in code that's not in any prove hot
        // path.
        alloc::vec![Self::ZERO; len]
    }
}

impl InjectiveMonomial<7> for PackedFelt {}

impl PermutationMonomial<7> for PackedFelt {
    fn injective_exp_root_n(&self) -> Self {
        exp_10540996611094048183(*self)
    }
}

impl_add_base_field!(PackedFelt, Felt);
impl_sub_base_field!(PackedFelt, Felt);
impl_mul_base_field!(PackedFelt, Felt);
impl_div_methods!(PackedFelt, Felt);
impl_sum_prod_base_field!(PackedFelt, Felt);

impl Algebra<Felt> for PackedFelt {
    /// Match the neon `BATCHED_LC_CHUNK = 2` — sensible default for a
    /// 2-lane packed type, but unprofiled on wasm32. The Plonky3 doc on
    /// this constant says it controls how many elements are processed per
    /// batch in linear-combination accumulation.
    /// TODO: tune empirically against the wallet's DEEP polynomial-eval
    /// hot path once a wasm32 microbench is wired up; current value is a
    /// guess inherited from neon.
    const BATCHED_LC_CHUNK: usize = 2;
}

impl_packed_value!(PackedFelt, Felt, WIDTH);

unsafe impl PackedField for PackedFelt {
    type Scalar = Felt;
}

/// Interleave two u64x2 vectors at the element level.
/// For block_len=1: [a0, a1] x [b0, b1] -> [a0, b0], [a1, b1]
#[inline]
fn interleave_u64(v0: v128, v1: v128) -> (v128, v128) {
    // i64x2_shuffle::<I0, I1>(a, b) selects lanes from concat(a; b), where
    // 0,1 are a's lanes and 2,3 are b's.
    let r0 = i64x2_shuffle::<0, 2>(v0, v1);
    let r1 = i64x2_shuffle::<1, 3>(v0, v1);
    (r0, r1)
}

unsafe impl PackedFieldPow2 for PackedFelt {
    fn interleave(&self, other: Self, block_len: usize) -> (Self, Self) {
        let (v0, v1) = (self.to_vector(), other.to_vector());
        let (res0, res1) = match block_len {
            1 => interleave_u64(v0, v1),
            2 => (v0, v1),
            _ => panic!("unsupported block length"),
        };
        (Self::from_vector(res0), Self::from_vector(res1))
    }
}

#[cfg(test)]
mod tests {
    //! These tests run on wasm32+simd128 only (the module is cfg-gated to
    //! that target). Native `cargo test` will NOT execute them. Run via:
    //!
    //!   wasm-pack test --node -p miden-field --features packed-felt-simd128
    //!
    //! Each `#[test]` is also annotated `#[wasm_bindgen_test]` so the
    //! wasm-pack runner picks them up. Bit-exact equivalence vs scalar
    //! Felt arithmetic.

    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    fn pack(a: u64, b: u64) -> PackedFelt {
        PackedFelt([Felt::new_unchecked(a), Felt::new_unchecked(b)])
    }

    #[test]
    #[wasm_bindgen_test]
    fn add_zero_and_one() {
        let zeros = PackedFelt::broadcast(Felt::ZERO);
        let ones = PackedFelt::broadcast(Felt::ONE);
        let result = zeros.add(ones);
        assert_eq!(result.0, [Felt::ONE, Felt::ONE]);

        let twos = ones.add(ones);
        assert_eq!(
            twos.0,
            [
                <Felt as PrimeCharacteristicRing>::TWO,
                <Felt as PrimeCharacteristicRing>::TWO,
            ]
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn sub_zero_and_one() {
        let ones = PackedFelt::broadcast(Felt::ONE);
        let zeros = PackedFelt::broadcast(Felt::ZERO);
        let result = ones.sub(ones);
        assert_eq!(result.0, [Felt::ZERO, Felt::ZERO]);

        // 0 - 1 wraps to P - 1.
        let result = zeros.sub(ones);
        assert_eq!(
            result.0,
            [
                <Felt as PrimeCharacteristicRing>::NEG_ONE,
                <Felt as PrimeCharacteristicRing>::NEG_ONE,
            ]
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn neg_zero_and_one() {
        let zeros = PackedFelt::broadcast(Felt::ZERO);
        assert_eq!(zeros.neg().0, [Felt::ZERO, Felt::ZERO]);

        let ones = PackedFelt::broadcast(Felt::ONE);
        assert_eq!(
            ones.neg().0,
            [
                <Felt as PrimeCharacteristicRing>::NEG_ONE,
                <Felt as PrimeCharacteristicRing>::NEG_ONE,
            ]
        );
    }

    /// Cross-check against scalar Felt for several edge cases.
    #[test]
    #[wasm_bindgen_test]
    fn add_edge_cases() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 1),
            (Felt::ORDER - 1, 1), // wraps to 0
            (Felt::ORDER - 1, Felt::ORDER - 1),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 1), // > P input — both impls should reduce
        ];
        for &(a, b) in cases {
            let pkg = pack(a, b);
            let sum_pkg = pkg.add(pkg);
            let scalar_a = Felt::new_unchecked(a) + Felt::new_unchecked(a);
            let scalar_b = Felt::new_unchecked(b) + Felt::new_unchecked(b);
            assert_eq!(
                sum_pkg.0,
                [scalar_a, scalar_b],
                "add mismatch for ({a:#x}, {b:#x})"
            );
        }
    }

    /// Cross-check subtraction against scalar Felt for several edge cases.
    /// `sub` has an independent overflow-detection branch from `add` (the
    /// `i64x2_gt(y_s, x_s)` mask + `u64x2_shr(mask, 32)` wrapback), so it
    /// gets its own coverage here even though the modular wrap behavior
    /// looks symmetric.
    #[test]
    #[wasm_bindgen_test]
    fn sub_edge_cases() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (0, 1),                                 // wraps to P-1
            (1, 0),
            (Felt::ORDER - 1, Felt::ORDER - 1),     // -> 0
            (1, Felt::ORDER - 1),                   // (1 - (-1)) mod P = 2
            (0, Felt::ORDER - 1),                   // -> 1
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            // Non-canonical (>P) inputs — both impls should still reduce.
            (0xFFFF_FFFF_FFFF_FFFF, 1),
            (1, 0xFFFF_FFFF_FFFF_FFFF),
        ];
        for &(a, b) in cases {
            let pkg_a = PackedFelt::broadcast(Felt::new_unchecked(a));
            let pkg_b = PackedFelt::broadcast(Felt::new_unchecked(b));
            let diff_pkg = pkg_a.sub(pkg_b);
            let scalar = Felt::new_unchecked(a) - Felt::new_unchecked(b);
            assert_eq!(
                diff_pkg.0,
                [scalar, scalar],
                "sub mismatch for ({a:#x} - {b:#x})"
            );
        }
    }

    /// Cross-check negation against scalar Felt for non-trivial inputs.
    /// `neg(P-1) == 1` and `neg` of `>P` (non-canonical) inputs both
    /// exercise the `canonicalize_s` step inside `neg`.
    #[test]
    #[wasm_bindgen_test]
    fn neg_edge_cases() {
        let cases: &[u64] = &[
            0,
            1,
            2,
            Felt::ORDER - 1,                  // expect 1
            Felt::ORDER - 2,                  // expect 2
            0xFFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,            // >P input — should canonicalize
            0x1234_5678_9ABC_DEF0,
        ];
        for &a in cases {
            let pkg_a = PackedFelt::broadcast(Felt::new_unchecked(a));
            let neg_pkg = pkg_a.neg();
            let scalar = -Felt::new_unchecked(a);
            assert_eq!(
                neg_pkg.0,
                [scalar, scalar],
                "neg mismatch for ({a:#x})"
            );
        }
    }

    /// Cross-check multiplication against scalar.
    #[test]
    #[wasm_bindgen_test]
    fn mul_edge_cases() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 1),
            (2, 3),
            (Felt::ORDER - 1, 2),
            // Worst-case for the reduce128 boundary: (P-1)^2 lands at the
            // top of the 128-bit product space.
            (Felt::ORDER - 1, Felt::ORDER - 1),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (0x1234_5678_9ABC_DEF0, 0xFEDC_BA98_7654_3210),
        ];
        for &(a, b) in cases {
            let pkg_a = PackedFelt::broadcast(Felt::new_unchecked(a));
            let pkg_b = PackedFelt::broadcast(Felt::new_unchecked(b));
            let prod_pkg = pkg_a.mul(pkg_b);
            let scalar = Felt::new_unchecked(a) * Felt::new_unchecked(b);
            assert_eq!(prod_pkg.0, [scalar, scalar], "mul mismatch for ({a:#x}, {b:#x})");
        }
    }

    /// Two-lane independence: lane 0 and lane 1 should produce the same
    /// result as if each were computed with scalar arithmetic in isolation.
    #[test]
    #[wasm_bindgen_test]
    fn two_lane_independence() {
        // Distinct values per lane to catch lane-swap bugs.
        let pkg_a = pack(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
        let pkg_b = pack(0x9999_AAAA_BBBB_CCCC, 0xDDDD_EEEE_FFFF_0001);
        let sum = pkg_a.add(pkg_b);
        let prod = pkg_a.mul(pkg_b);
        assert_eq!(
            sum.0,
            [pkg_a.0[0] + pkg_b.0[0], pkg_a.0[1] + pkg_b.0[1]]
        );
        assert_eq!(
            prod.0,
            [pkg_a.0[0] * pkg_b.0[0], pkg_a.0[1] * pkg_b.0[1]]
        );
    }

    /// Cross-check `halve` against scalar `Felt::halve` for both even and
    /// odd inputs (odd needs the `+ (P+1)/2` fix-up).
    #[test]
    #[wasm_bindgen_test]
    fn halve_matches_scalar() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (2, 4),                                  // both even
            (1, 3),                                  // both odd
            (0xFFFF_FFFE, 0xFFFF_FFFF),              // (even, odd) mixed lanes
            (Felt::ORDER - 2, Felt::ORDER - 1),      // near-P even/odd
        ];
        for &(a, b) in cases {
            let pkg = pack(a, b);
            let halved = <PackedFelt as PrimeCharacteristicRing>::halve(&pkg);
            let exp_a = <Felt as PrimeCharacteristicRing>::halve(&Felt::new_unchecked(a));
            let exp_b = <Felt as PrimeCharacteristicRing>::halve(&Felt::new_unchecked(b));
            assert_eq!(halved.0, [exp_a, exp_b], "halve mismatch for ({a:#x}, {b:#x})");
        }
    }

    /// Cross-check `square` against scalar.
    #[test]
    #[wasm_bindgen_test]
    fn square_matches_scalar() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 2),
            (Felt::ORDER - 1, 0xDEAD_BEEF_CAFE_BABE),
        ];
        for &(a, b) in cases {
            let pkg = pack(a, b);
            let sq = <PackedFelt as PrimeCharacteristicRing>::square(&pkg);
            let exp_a = <Felt as PrimeCharacteristicRing>::square(&Felt::new_unchecked(a));
            let exp_b = <Felt as PrimeCharacteristicRing>::square(&Felt::new_unchecked(b));
            assert_eq!(sq.0, [exp_a, exp_b], "square mismatch for ({a:#x}, {b:#x})");
        }
    }

    /// `interleave(block_len=1)`: [a0, a1] x [b0, b1] -> ([a0, b0], [a1, b1]).
    /// `interleave(block_len=2)`: identity (both inputs already block-sized 2).
    #[test]
    #[wasm_bindgen_test]
    fn interleave_block_len_1_and_2() {
        let v0 = pack(1, 2);
        let v1 = pack(3, 4);
        let (r0, r1) = v0.interleave(v1, 1);
        assert_eq!(r0.0, [Felt::new_unchecked(1), Felt::new_unchecked(3)]);
        assert_eq!(r1.0, [Felt::new_unchecked(2), Felt::new_unchecked(4)]);

        let (r0, r1) = v0.interleave(v1, 2);
        assert_eq!(r0.0, [Felt::new_unchecked(1), Felt::new_unchecked(2)]);
        assert_eq!(r1.0, [Felt::new_unchecked(3), Felt::new_unchecked(4)]);
    }

    // ========================================================================
    // PackedFelt vs scalar Felt arithmetic micro-bench.
    //
    // Goal: demonstrate that the wasm32+simd128 PackedFelt path is faster
    // than running the same arithmetic twice with scalar Felt.
    //
    // Methodology: run N iterations of the operation, time via
    // `js_sys::Date::now()` (millisecond resolution — fine for N >= ~10k).
    // Print results to the wasm-pack test log. Assert the packed runtime is
    // within reason of the scalar runtime (catches egregious regressions
    // like a missing `target_feature = "+simd128"` build flag).
    //
    // This is NOT a microsecond-precision bench — for that, use a
    // criterion-style harness from a real wasm prover bench. This version
    // gives you a "is the simd128 path actually exercised" sanity number.
    //
    // Run via: wasm-pack test --node -p miden-field --features packed-felt-simd128
    // (the timing print only shows up with `wasm-pack test --node`'s
    // captured stdout; use --release for meaningful numbers).
    // ========================================================================

    /// Iteration count for the micro-bench. Must be high enough that the
    /// total runtime exceeds Date.now()'s millisecond resolution by a
    /// healthy margin.
    const BENCH_ITERS: usize = 200_000;

    fn now_ms() -> f64 {
        js_sys::Date::now()
    }

    // Direct binding to the host's `console.log`. Printed to wasm-pack's
    // captured node stdout in `wasm-pack test --node`, and to the
    // browser console in `wasm-pack test --headless --chrome`.
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn log(s: &str);
    }

    fn console_log(msg: &str) {
        log(msg);
    }

    #[test]
    #[wasm_bindgen_test]
    fn bench_packed_vs_scalar_mul() {
        // Two interesting non-trivial values — chosen so reduce128 has
        // real work to do, not zero-length carries.
        let pkg_a = pack(0x1234_5678_9ABC_DEF0, 0xFEDC_BA98_7654_3210);
        let pkg_b = pack(0xCAFE_BABE_DEAD_BEEF, 0x0123_4567_89AB_CDEF);
        let scalar_a0 = Felt::new_unchecked(0x1234_5678_9ABC_DEF0);
        let scalar_a1 = Felt::new_unchecked(0xFEDC_BA98_7654_3210);
        let scalar_b0 = Felt::new_unchecked(0xCAFE_BABE_DEAD_BEEF);
        let scalar_b1 = Felt::new_unchecked(0x0123_4567_89AB_CDEF);

        // Warm-up.
        for _ in 0..1024 {
            let _ = core::hint::black_box(pkg_a) * core::hint::black_box(pkg_b);
        }

        // Packed: one PackedFelt::mul == 2 lane multiplies.
        let t0 = now_ms();
        let mut acc = pkg_a;
        for _ in 0..BENCH_ITERS {
            acc = core::hint::black_box(acc) * core::hint::black_box(pkg_b);
        }
        let packed_ms = now_ms() - t0;
        core::hint::black_box(acc);

        // Scalar: 2 Felt::mul calls (matched lane count to the packed
        // operation so the comparison is workload-equivalent).
        let t0 = now_ms();
        let mut acc0 = scalar_a0;
        let mut acc1 = scalar_a1;
        for _ in 0..BENCH_ITERS {
            acc0 = core::hint::black_box(acc0) * core::hint::black_box(scalar_b0);
            acc1 = core::hint::black_box(acc1) * core::hint::black_box(scalar_b1);
        }
        let scalar_ms = now_ms() - t0;
        core::hint::black_box((acc0, acc1));

        let speedup = scalar_ms / packed_ms;
        console_log(&alloc::format!(
            "[bench] PackedFelt::mul vs 2x Felt::mul over {BENCH_ITERS} iters: \
             packed={packed_ms:.1}ms  scalar={scalar_ms:.1}ms  speedup={speedup:.2}x"
        ));

        // Sanity bound — packed should not be MORE than 1.5x slower than
        // scalar even in adversarial timing. With +simd128 enabled and a
        // release build, expect ~1.5-2.0x speedup. With +simd128 missing,
        // packed degrades to scalar+overhead which is roughly equal-or-
        // slower. With opt-level=0, all bets are off (don't run there).
        assert!(
            packed_ms < scalar_ms * 1.5,
            "PackedFelt::mul is unexpectedly slow: \
             packed={packed_ms:.1}ms  scalar={scalar_ms:.1}ms  \
             speedup={speedup:.2}x — is +simd128 enabled and build in release?"
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn bench_packed_vs_scalar_add() {
        // Mirror of mul bench with addition (which exercises a different
        // SIMD path: i64x2_add + epsilon-correction, no full reduce128).
        let pkg_a = pack(0x1234_5678_9ABC_DEF0, 0xFEDC_BA98_7654_3210);
        let pkg_b = pack(0xCAFE_BABE_DEAD_BEEF, 0x0123_4567_89AB_CDEF);
        let scalar_a0 = Felt::new_unchecked(0x1234_5678_9ABC_DEF0);
        let scalar_a1 = Felt::new_unchecked(0xFEDC_BA98_7654_3210);
        let scalar_b0 = Felt::new_unchecked(0xCAFE_BABE_DEAD_BEEF);
        let scalar_b1 = Felt::new_unchecked(0x0123_4567_89AB_CDEF);

        for _ in 0..1024 {
            let _ = core::hint::black_box(pkg_a) + core::hint::black_box(pkg_b);
        }

        let t0 = now_ms();
        let mut acc = pkg_a;
        for _ in 0..BENCH_ITERS {
            acc = core::hint::black_box(acc) + core::hint::black_box(pkg_b);
        }
        let packed_ms = now_ms() - t0;
        core::hint::black_box(acc);

        let t0 = now_ms();
        let mut acc0 = scalar_a0;
        let mut acc1 = scalar_a1;
        for _ in 0..BENCH_ITERS {
            acc0 = core::hint::black_box(acc0) + core::hint::black_box(scalar_b0);
            acc1 = core::hint::black_box(acc1) + core::hint::black_box(scalar_b1);
        }
        let scalar_ms = now_ms() - t0;
        core::hint::black_box((acc0, acc1));

        let speedup = scalar_ms / packed_ms;
        console_log(&alloc::format!(
            "[bench] PackedFelt::add vs 2x Felt::add over {BENCH_ITERS} iters: \
             packed={packed_ms:.1}ms  scalar={scalar_ms:.1}ms  speedup={speedup:.2}x"
        ));

        assert!(
            packed_ms < scalar_ms * 1.5,
            "PackedFelt::add is unexpectedly slow: \
             packed={packed_ms:.1}ms  scalar={scalar_ms:.1}ms  \
             speedup={speedup:.2}x — is +simd128 enabled and build in release?"
        );
    }
}
