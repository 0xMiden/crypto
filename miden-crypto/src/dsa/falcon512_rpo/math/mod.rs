//! Contains different structs and methods related to the Falcon DSA.
//!
//! It uses and acknowledges the work in:
//!
//! 1. The [reference](https://falcon-sign.info/impl/README.txt.html) implementation by Thomas
//!    Pornin.
//! 2. The [Rust](https://github.com/aszepieniec/falcon-rust) implementation by Alan Szepieniec.
use alloc::vec::Vec;
use core::ops::MulAssign;

use num::{One, Zero};
use num_complex::Complex64;

use super::MODULUS;

// Core types
mod fft;
pub use fft::FastFft;

mod field;
pub use field::FalconFelt;

mod polynomial;
pub use polynomial::Polynomial;

// FLR (Floating-point Linear Real) implementation
pub(crate) mod flr;

// FN-DSA (FIPS 204 Falcon) implementation
pub(crate) mod fndsa;
pub(crate) use fndsa::ntru_gen;

pub trait Inverse: Copy + Zero + MulAssign + One {
    /// Gets the inverse of a, or zero if it is zero.
    fn inverse_or_zero(self) -> Self;

    /// Gets the inverses of a batch of elements, and skip over any that are zero.
    fn batch_inverse_or_zero(batch: &[Self]) -> Vec<Self> {
        let mut acc = Self::one();
        let mut rp: Vec<Self> = Vec::with_capacity(batch.len());
        for batch_item in batch {
            if !batch_item.is_zero() {
                rp.push(acc);
                acc = *batch_item * acc;
            } else {
                rp.push(Self::zero());
            }
        }
        let mut inv = Self::inverse_or_zero(acc);
        for i in (0..batch.len()).rev() {
            if !batch[i].is_zero() {
                rp[i] *= inv;
                inv *= batch[i];
            }
        }
        rp
    }
}

impl Inverse for Complex64 {
    fn inverse_or_zero(self) -> Self {
        let modulus = self.re * self.re + self.im * self.im;
        Complex64::new(self.re / modulus, -self.im / modulus)
    }
    fn batch_inverse_or_zero(batch: &[Self]) -> Vec<Self> {
        batch.iter().map(|&c| Complex64::new(1.0, 0.0) / c).collect()
    }
}

impl Inverse for f64 {
    fn inverse_or_zero(self) -> Self {
        1.0 / self
    }
    fn batch_inverse_or_zero(batch: &[Self]) -> Vec<Self> {
        batch.iter().map(|&c| 1.0 / c).collect()
    }
}
