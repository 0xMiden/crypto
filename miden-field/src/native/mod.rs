//! Off-chain implementation of [`crate::Felt`].

use alloc::format;
use core::{
    array, fmt,
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Deref, DerefMut, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_bigint::BigUint;
use p3_challenger::UniformSamplingField;
use p3_field::{
    Field, InjectiveMonomial, Packable, PermutationMonomial, PrimeCharacteristicRing, PrimeField,
    PrimeField64, RawDataSerializable, TwoAdicField,
    extension::{BinomiallyExtendable, BinomiallyExtendableAlgebra, HasTwoAdicBinomialExtension},
    impl_raw_serializable_primefield64,
    integers::QuotientMap,
    quotient_map_large_iint, quotient_map_large_uint, quotient_map_small_int,
};
use p3_goldilocks::Goldilocks;
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

/// A `Felt` backed by Plonky3's Goldilocks field element.
#[derive(Copy, Clone, Default, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct Felt(Goldilocks);

impl Felt {
    /// Creates a new field element from any `u64`.
    ///
    /// Any `u64` value is accepted. No reduction is performed since Goldilocks uses a
    /// non-canonical internal representation.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(Goldilocks::new(value))
    }
}

impl miden_serde_utils::Serializable for Felt {
    fn write_into<W: miden_serde_utils::ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.as_canonical_u64());
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl miden_serde_utils::Deserializable for Felt {
    fn read_from<R: miden_serde_utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_serde_utils::DeserializationError> {
        let value = source.read_u64()?;
        Self::from_canonical_checked(value).ok_or_else(|| {
            miden_serde_utils::DeserializationError::InvalidValue(format!(
                "value {value} is not a valid felt"
            ))
        })
    }
}

impl PrimeCharacteristicRing for Felt {
    type PrimeSubfield = Goldilocks;

    const ZERO: Self = Self(Goldilocks::ZERO);
    const ONE: Self = Self(Goldilocks::ONE);
    const TWO: Self = Self(Goldilocks::TWO);
    const NEG_ONE: Self = Self(Goldilocks::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self(f)
    }

    #[inline]
    fn from_bool(value: bool) -> Self {
        Self::new(value.into())
    }

    #[inline]
    fn halve(&self) -> Self {
        Self(self.0.halve())
    }

    #[inline]
    fn mul_2exp_u64(&self, exp: u64) -> Self {
        Self(self.0.mul_2exp_u64(exp))
    }

    #[inline]
    fn div_2exp_u64(&self, exp: u64) -> Self {
        Self(self.0.div_2exp_u64(exp))
    }

    #[inline]
    fn exp_u64(&self, power: u64) -> Self {
        self.0.exp_u64(power).into()
    }
}

quotient_map_small_int!(Felt, u64, [u8, u16, u32]);
quotient_map_small_int!(Felt, i64, [i8, i16, i32]);

quotient_map_large_uint!(
    Felt,
    u64,
    Felt::ORDER_U64,
    "`[0, 2^64 - 2^32]`",
    "`[0, 2^64 - 1]`",
    [u128]
);
quotient_map_large_iint!(
    Felt,
    i64,
    "`[-(2^63 - 2^31), 2^63 - 2^31]`",
    "`[1 + 2^32 - 2^64, 2^64 - 1]`",
    [(i128, u128)]
);

impl QuotientMap<u64> for Felt {
    #[inline]
    fn from_int(int: u64) -> Self {
        Goldilocks::from_int(int).into()
    }

    #[inline]
    fn from_canonical_checked(int: u64) -> Option<Self> {
        Goldilocks::from_canonical_checked(int).map(From::from)
    }

    #[inline(always)]
    unsafe fn from_canonical_unchecked(int: u64) -> Self {
        Goldilocks::new(int).into()
    }
}

impl QuotientMap<i64> for Felt {
    #[inline]
    fn from_int(int: i64) -> Self {
        Goldilocks::from_int(int).into()
    }

    #[inline]
    fn from_canonical_checked(int: i64) -> Option<Self> {
        Goldilocks::from_canonical_checked(int).map(From::from)
    }

    #[inline(always)]
    unsafe fn from_canonical_unchecked(int: i64) -> Self {
        unsafe { Goldilocks::from_canonical_unchecked(int).into() }
    }
}

impl PrimeField for Felt {
    #[inline]
    fn as_canonical_biguint(&self) -> BigUint {
        <Goldilocks as PrimeField>::as_canonical_biguint(&self.0)
    }
}

impl PrimeField64 for Felt {
    const ORDER_U64: u64 = <Goldilocks as PrimeField64>::ORDER_U64;

    #[inline]
    fn as_canonical_u64(&self) -> u64 {
        self.0.as_canonical_u64()
    }
}

impl TwoAdicField for Felt {
    const TWO_ADICITY: usize = <Goldilocks as TwoAdicField>::TWO_ADICITY;

    #[inline]
    fn two_adic_generator(bits: usize) -> Self {
        Self(<Goldilocks as TwoAdicField>::two_adic_generator(bits))
    }
}

// EXTENSION FIELDS
// ================================================================================================

impl BinomiallyExtendableAlgebra<Self, 2> for Felt {}

impl BinomiallyExtendable<2> for Felt {
    const W: Self = Self(<Goldilocks as BinomiallyExtendable<2>>::W);

    const DTH_ROOT: Self = Self(<Goldilocks as BinomiallyExtendable<2>>::DTH_ROOT);

    const EXT_GENERATOR: [Self; 2] = [
        Self(<Goldilocks as BinomiallyExtendable<2>>::EXT_GENERATOR[0]),
        Self(<Goldilocks as BinomiallyExtendable<2>>::EXT_GENERATOR[1]),
    ];
}

impl HasTwoAdicBinomialExtension<2> for Felt {
    const EXT_TWO_ADICITY: usize = <Goldilocks as HasTwoAdicBinomialExtension<2>>::EXT_TWO_ADICITY;

    #[inline]
    fn ext_two_adic_generator(bits: usize) -> [Self; 2] {
        let [a, b] = <Goldilocks as HasTwoAdicBinomialExtension<2>>::ext_two_adic_generator(bits);
        [Self(a), Self(b)]
    }
}

impl BinomiallyExtendableAlgebra<Self, 5> for Felt {}

impl BinomiallyExtendable<5> for Felt {
    const W: Self = Self(<Goldilocks as BinomiallyExtendable<5>>::W);

    const DTH_ROOT: Self = Self(<Goldilocks as BinomiallyExtendable<5>>::DTH_ROOT);

    const EXT_GENERATOR: [Self; 5] = [
        Self(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR[0]),
        Self(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR[1]),
        Self(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR[2]),
        Self(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR[3]),
        Self(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR[4]),
    ];
}

impl HasTwoAdicBinomialExtension<5> for Felt {
    const EXT_TWO_ADICITY: usize = <Goldilocks as HasTwoAdicBinomialExtension<5>>::EXT_TWO_ADICITY;

    #[inline]
    fn ext_two_adic_generator(bits: usize) -> [Self; 5] {
        let ext_generator =
            <Goldilocks as HasTwoAdicBinomialExtension<5>>::ext_two_adic_generator(bits);
        [
            Self(ext_generator[0]),
            Self(ext_generator[1]),
            Self(ext_generator[2]),
            Self(ext_generator[3]),
            Self(ext_generator[4]),
        ]
    }
}

impl RawDataSerializable for Felt {
    impl_raw_serializable_primefield64!();
}

impl Packable for Felt {}

impl Field for Felt {
    type Packing = Self;

    const GENERATOR: Self = Self(Goldilocks::GENERATOR);

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    #[inline]
    fn try_inverse(&self) -> Option<Self> {
        self.0.try_inverse().map(Self)
    }

    #[inline]
    fn order() -> BigUint {
        <Goldilocks as Field>::order()
    }
}

impl Distribution<Felt> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Felt {
        let inner = <StandardUniform as Distribution<Goldilocks>>::sample(self, rng);
        Felt(inner)
    }
}

impl UniformSamplingField for Felt {
    const MAX_SINGLE_SAMPLE_BITS: usize =
        <Goldilocks as UniformSamplingField>::MAX_SINGLE_SAMPLE_BITS;
    const SAMPLING_BITS_M: [u64; 64] = <Goldilocks as UniformSamplingField>::SAMPLING_BITS_M;
}

impl InjectiveMonomial<7> for Felt {}

impl PermutationMonomial<7> for Felt {
    #[inline]
    fn injective_exp_root_n(&self) -> Self {
        Self(self.0.injective_exp_root_n())
    }
}

impl Deref for Felt {
    type Target = Goldilocks;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Felt {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Goldilocks> for Felt {
    #[inline]
    fn from(value: Goldilocks) -> Self {
        Self(value)
    }
}

impl From<Felt> for Goldilocks {
    #[inline]
    fn from(value: Felt) -> Self {
        value.0
    }
}

impl Add for Felt {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign for Felt {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for Felt {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl SubAssign for Felt {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Mul for Felt {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl MulAssign for Felt {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Div for Felt {
    type Output = Self;

    #[inline]
    fn div(self, other: Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl DivAssign for Felt {
    #[inline]
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl Neg for Felt {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl PartialEq for Felt {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Goldilocks> for Felt {
    #[inline]
    fn eq(&self, other: &Goldilocks) -> bool {
        self.0 == *other
    }
}

impl Eq for Felt {}

impl PartialOrd for Felt {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Felt {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl fmt::Display for Felt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for Felt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Hash for Felt {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.as_canonical_u64());
    }
}

impl Sum for Felt {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self(iter.map(|x| x.0).sum())
    }
}

impl<'a> Sum<&'a Felt> for Felt {
    #[inline]
    fn sum<I: Iterator<Item = &'a Felt>>(iter: I) -> Self {
        Self(iter.map(|x| x.0).sum())
    }
}

impl Product for Felt {
    #[inline]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self(iter.map(|x| x.0).product())
    }
}

impl<'a> Product<&'a Felt> for Felt {
    #[inline]
    fn product<I: Iterator<Item = &'a Felt>>(iter: I) -> Self {
        Self(iter.map(|x| x.0).product())
    }
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(all(any(test, feature = "testing"), not(all(target_family = "wasm", miden))))]
mod arbitrary {
    use p3_field::PrimeField64;
    use proptest::prelude::*;

    use super::Felt;

    impl Arbitrary for Felt {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            let canonical = (0u64..Felt::ORDER_U64).prop_map(Felt::new).boxed();
            // Goldilocks uses representation where values above the field order are valid and
            // represent wrapped field elements. Generate such values 1/5 of the time to exercise
            // this behavior.
            let non_canonical = (Felt::ORDER_U64..=u64::MAX).prop_map(Felt::new).boxed();
            prop_oneof![4 => canonical, 1 => non_canonical].no_shrink().boxed()
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests;
