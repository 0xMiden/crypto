use alloc::string::String;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num::{One, Zero};

use super::{Inverse, MODULUS};

// ================================================================================================
// FIELD ELEMENT REPRESENTATIONS
// ================================================================================================
//
// Falcon operates over the finite field Z/qZ where q = 12289. Field elements can be represented
// in several different ways depending on the context. This module uses multiple representations
// for efficiency and compatibility with different parts of the algorithm.
//
// ## 1. EXTERNAL REPRESENTATION [0, q-1]
//
// The standard mathematical representation of field elements as unsigned integers in [0, q-1].
// - Used for: Public API, serialization, interoperability
// - Zero is represented as: 0
// - Example: 0, 1, 2, ..., 12288
//
// ## 2. INTERNAL REPRESENTATION [1, q]
//
// Montgomery arithmetic optimization where zero is represented as q instead of 0.
// - Used for: Internal storage in FalconFelt, Montgomery operations
// - Zero is represented as: q (12289)
// - Example: 1, 2, 3, ..., 12289 (where 12289 = 0)
// - Why: Avoids a conditional branch in Montgomery reduction (mq_mred)
//
// Conversion between external and internal:
// - External → Internal: if x == 0 then q else x
// - Internal → Extern: if x == q then 0 else x
//
// ## 3. SIGNED/BALANCED REPRESENTATION [-(q-1)/2, (q-1)/2]
//
// Centered representation where values are in the symmetric range around zero.
// - Used for: Signature coefficients, key material, lattice vectors
// - Zero is represented as: 0
// - Range: -6144 to +6144
// - Example: -1 instead of 12288, -5 instead of 12284
//
// Why needed: In lattice-based cryptography, secret keys and signatures consist of "small"
// values. Representing -1 as 12288 would incorrectly make it appear "large". The balanced
// representation preserves the smallness property.
//
// Conversion:
// - External → Balanced: if x > (q-1)/2 then x - q else x
// - Balanced → External: if x < 0 then x + q else x
//
// ## 4. MONTGOMERY REPRESENTATION
//
// Not a separate storage format, but a computational technique used during field arithmetic.
// A value x in Montgomery representation = (x * R) mod q, where R = 2^32.
//
// Montgomery multiplication of a and b:
//   mq_mmul(a, b) = (a * b) / R mod q
//
// Note: Our internal representation [1, q] is NOT in Montgomery form. We only temporarily
// convert to Montgomery form during multiplication operations.
//
// ## SUMMARY OF WHEN EACH IS USED
//
// ```
// FalconFelt::new(u16)          ← Takes external [0, q-1]
// FalconFelt.value()            → Returns external [0, q-1]
// FalconFelt.balanced_value()   → Returns balanced [-(q-1)/2, (q-1)/2]
// FalconFelt.0 (internal)       ← Stored as internal [1, q]
// FalconFelt::from(i16)         ← Takes signed, converts to external, then internal
// mq_add/mq_sub/mq_mmul         ← Operate on internal [1, q]
// ```
//
// ================================================================================================
// MONTGOMERY ARITHMETIC (from fn-dsa-comm)
// ================================================================================================
// The following functions are adapted from rust-fn-dsa:
// https://github.com/pornin/rust-fn-dsa/blob/main/fn-dsa-comm/src/mq.rs
//
// All Montgomery operations work on internal representation [1, q].
// Montgomery multiplication uses R = 2^32 for efficient multiplication without expensive
// modular reduction.

const Q: u32 = MODULUS as u32;

// -1/q mod 2^32
const Q1I: u32 = 4143984639;

// 2^64 mod q (R^2 mod q, where R = 2^32)
const R2: u32 = 5664;

/// Addition modulo q (internal representation [1,q]).
#[inline(always)]
fn mq_add(x: u32, y: u32) -> u32 {
    let a = Q.wrapping_sub(x + y);
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}

/// Subtraction modulo q (internal representation [1,q]).
#[inline(always)]
fn mq_sub(x: u32, y: u32) -> u32 {
    let a = y.wrapping_sub(x);
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}

/// Montgomery reduction: x/2^32 mod q.
/// Input must satisfy 1 <= x <= 3489673216.
#[inline(always)]
fn mq_mred(x: u32) -> u32 {
    let b = x.wrapping_mul(Q1I);
    let c = (b >> 16) * Q;
    (c >> 16) + 1
}

/// Montgomery multiplication modulo q (internal representation [1,q]).
#[inline(always)]
fn mq_mmul(x: u32, y: u32) -> u32 {
    mq_mred(x * y)
}

/// Division modulo q (internal representation [1,q]).
/// Returns 0 if divisor is 0.
fn mq_div(x: u32, y: u32) -> u32 {
    // Convert y to Montgomery representation
    let y = mq_mmul(y, R2);

    // Compute 1/y = y^(q-2) using addition chain
    let y2 = mq_mmul(y, y);
    let y3 = mq_mmul(y2, y);
    let y5 = mq_mmul(y3, y2);
    let y10 = mq_mmul(y5, y5);
    let y20 = mq_mmul(y10, y10);
    let y40 = mq_mmul(y20, y20);
    let y80 = mq_mmul(y40, y40);
    let y160 = mq_mmul(y80, y80);
    let y163 = mq_mmul(y160, y3);
    let y323 = mq_mmul(y163, y160);
    let y646 = mq_mmul(y323, y323);
    let y1292 = mq_mmul(y646, y646);
    let y1455 = mq_mmul(y1292, y163);
    let y2910 = mq_mmul(y1455, y1455);
    let y5820 = mq_mmul(y2910, y2910);
    let y6143 = mq_mmul(y5820, y323);
    let y12286 = mq_mmul(y6143, y6143);
    let iy = mq_mmul(y12286, y);

    // Multiply by x to get x/y
    mq_mmul(x, iy)
}

/// Convert signed integer to external representation [0, q-1].
///
/// This implements fn-dsa's mqpoly_signed_to_ext logic using bit manipulation
/// to avoid branching:
/// - For positive x: x remains unchanged (x >> 16 = 0, so we add 0)
/// - For negative x: x + q (x >> 16 = 0xFFFF, so we add q)
///
/// Examples:
/// - signed_to_external(5) = 5
/// - signed_to_external(-1) = 12288
/// - signed_to_external(-6144) = 6145
#[inline(always)]
fn signed_to_external(value: i32) -> u16 {
    let x = value as u32;
    (x.wrapping_add((x >> 16) & Q)) as u16
}

// ================================================================================================
// FALCONFELT - Field element wrapper with internal representation
// ================================================================================================
// Values are stored in internal representation [1, q] for compatibility with Montgomery arithmetic.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FalconFelt(u16);

impl FalconFelt {
    /// Create a new field element from a u16 value in external representation [0, q-1].
    ///
    /// Converts from external to internal representation [1, q] for storage.
    /// - Input 0 becomes q (12289)
    /// - Input 1..12288 remain unchanged
    ///
    /// This uses fn-dsa's mqpoly_ext_to_int logic with bit manipulation to avoid branching.
    pub const fn new(value: u16) -> Self {
        // Convert from external [0, q-1] to internal [1, q]
        // If value == 0, we want q; otherwise keep value
        // Branchless: if x == 0 then x.wrapping_sub(1) = 0xFFFF..., so (x-1) >> 16 = 0xFFFF
        let x = value as u32;
        let internal = (x + (Q & (x.wrapping_sub(1) >> 16))) as u16;
        FalconFelt(internal)
    }

    /// Get the value as a u16 in external representation [0, q-1].
    ///
    /// Converts from internal representation [1, q] to external [0, q-1].
    /// - Internal q (12289) becomes 0
    /// - Internal 1..12288 remain unchanged
    ///
    /// This uses fn-dsa's mqpoly_int_to_ext logic with bit manipulation to avoid branching.
    pub const fn value(&self) -> u16 {
        // Convert from internal [1, q] to external [0, q-1]
        // If self.0 == q, result should be 0
        // Branchless: (q - q) = 0, then 0.wrapping_add(q & 0) = 0
        //            (x - q) < 0 has high bit set, so (x-q) >> 16 = 0xFFFF
        let x = (self.0 as u32).wrapping_sub(Q);
        (x.wrapping_add(Q & (x >> 16))) as u16
    }

    /// Get the value in balanced/signed representation [-(q-1)/2, (q-1)/2].
    ///
    /// This representation is used for signature coefficients and key material in lattice-based
    /// cryptography, where we need to preserve the "smallness" of values like -1 (not 12288).
    ///
    /// Examples:
    /// - External 0 → Balanced 0
    /// - External 1 → Balanced 1
    /// - External 6144 → Balanced 6144
    /// - External 6145 → Balanced -6144
    /// - External 12288 → Balanced -1
    pub fn balanced_value(&self) -> i16 {
        let v = self.value() as i16;
        // Branchless: if v > q/2, subtract q; otherwise keep v
        let g = (v > (MODULUS / 2)) as i16;
        v - MODULUS * g
    }

    /// Multiply two field elements (used for const contexts).
    pub const fn multiply(&self, other: Self) -> Self {
        // Use simple modular multiplication for const context
        FalconFelt(((self.0 as u64 * other.0 as u64) % Q as u64) as u16)
    }
}

impl Add for FalconFelt {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        FalconFelt(mq_add(self.0 as u32, rhs.0 as u32) as u16)
    }
}

impl AddAssign for FalconFelt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FalconFelt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        FalconFelt(mq_sub(self.0 as u32, rhs.0 as u32) as u16)
    }
}

impl SubAssign for FalconFelt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for FalconFelt {
    type Output = FalconFelt;

    fn neg(self) -> Self::Output {
        // In internal representation, negation is Q - x, but if x == Q (representing 0), result is
        // Q
        let x = self.0 as u32;
        FalconFelt((Q - x + Q * ((x == Q) as u32)) as u16)
    }
}

impl Mul for FalconFelt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // Montgomery multiplication needs to multiply by R2 to get correct result
        // This matches fn-dsa's mqpoly_mul_ntt implementation
        FalconFelt(mq_mmul(mq_mmul(self.0 as u32, rhs.0 as u32), R2) as u16)
    }
}

impl MulAssign for FalconFelt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for FalconFelt {
    type Output = FalconFelt;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse_or_zero()
    }
}

impl DivAssign for FalconFelt {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Zero for FalconFelt {
    fn zero() -> Self {
        FalconFelt::new(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == Q as u16
    }
}

impl One for FalconFelt {
    fn one() -> Self {
        FalconFelt::new(1)
    }
}

impl Inverse for FalconFelt {
    fn inverse_or_zero(self) -> Self {
        // Use fn-dsa's division: 1/x = mq_div(1, x)
        // FalconFelt(1) in internal representation is 1
        FalconFelt(mq_div(1, self.0 as u32) as u16)
    }
}

impl From<i16> for FalconFelt {
    /// Convert a signed i16 to a field element.
    ///
    /// This is used when working with signature coefficients and key material, which are
    /// typically stored as small signed integers (e.g., -5, 3, -1).
    ///
    /// Conversion path: signed i16 → external u16 [0, q-1] → internal u16 [1, q]
    ///
    /// Examples:
    /// - From::from(5i16) creates FalconFelt storing 5
    /// - From::from(-1i16) creates FalconFelt storing 12289 (internally 12288 externally)
    fn from(value: i16) -> Self {
        FalconFelt::new(signed_to_external(value as i32))
    }
}

impl From<i8> for FalconFelt {
    /// Convert a signed i8 to a field element.
    ///
    /// This is used when working with key material which uses i8 for storage efficiency.
    ///
    /// Conversion path: signed i8 → external u16 [0, q-1] → internal u16 [1, q]
    fn from(value: i8) -> Self {
        FalconFelt::new(signed_to_external(value as i32))
    }
}

impl TryFrom<u32> for FalconFelt {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= MODULUS as u32 {
            Err(format!("value {value} is greater than or equal to the field modulus {MODULUS}"))
        } else {
            Ok(FalconFelt::new(value as u16))
        }
    }
}
