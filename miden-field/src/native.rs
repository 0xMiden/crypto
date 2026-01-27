//! Off-chain implementation of [`crate::Felt`].

use alloc::string::String;
use core::{
    fmt,
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Deref, DerefMut, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_bigint::BigUint;
use p3_field::{
    Field, Packable, PrimeCharacteristicRing, PrimeField, PrimeField64, RawDataSerializable,
    TwoAdicField, integers::QuotientMap,
};
use p3_goldilocks::Goldilocks;

/// A `Felt` backed by Plonky3's Goldilocks field element.
#[derive(Copy, Clone, Default, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct Felt(pub Goldilocks);

impl Felt {
    /// Creates a new field element from any `u64`.
    ///
    /// Any `u64` value is accepted. No reduction is performed since Goldilocks uses a
    /// non-canonical internal representation.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(Goldilocks::new(value))
    }

    /// Returns the representative of this felt in canonical form in the range `[0, ORDER_U64)`.
    #[inline]
    pub fn as_canonical_u64(&self) -> u64 {
        self.0.as_canonical_u64()
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
            use core::fmt::Write;

            let mut msg = String::new();
            write!(&mut msg, "value {value} is not a valid felt")
                .expect("writing to string should not fail");
            miden_serde_utils::DeserializationError::InvalidValue(msg)
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
}

macro_rules! impl_quotient_map {
    ($($int:ty),* $(,)?) => {
        $(
            impl QuotientMap<$int> for Felt {
                #[inline]
                fn from_int(int: $int) -> Self {
                    Self(<Goldilocks as QuotientMap<$int>>::from_int(int))
                }

                #[inline]
                fn from_canonical_checked(int: $int) -> Option<Self> {
                    <Goldilocks as QuotientMap<$int>>::from_canonical_checked(int).map(Self)
                }

                #[inline]
                unsafe fn from_canonical_unchecked(int: $int) -> Self {
                    Self(unsafe { <Goldilocks as QuotientMap<$int>>::from_canonical_unchecked(int) })
                }
            }
        )*
    };
}

impl_quotient_map!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

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

impl RawDataSerializable for Felt {
    const NUM_BYTES: usize = core::mem::size_of::<u64>();

    #[inline]
    fn into_bytes(self) -> impl IntoIterator<Item = u8> {
        self.as_canonical_u64().to_le_bytes()
    }
}

impl Packable for Felt {}

impl Field for Felt {
    type Packing = Self;

    const GENERATOR: Self = Self(Goldilocks::GENERATOR);

    #[inline]
    fn try_inverse(&self) -> Option<Self> {
        self.0.try_inverse().map(Self)
    }

    #[inline]
    fn order() -> BigUint {
        <Goldilocks as Field>::order()
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

impl Felt {
    /// Field element representing zero.
    pub const ZERO: Self = Self(Goldilocks::ZERO);
    /// Field element representing one.
    pub const ONE: Self = Self(Goldilocks::ONE);
    /// Field element representing two.
    pub const TWO: Self = Self(Goldilocks::TWO);
    /// Field element representing -1.
    pub const NEG_ONE: Self = Self(Goldilocks::NEG_ONE);
}
