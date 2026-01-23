//! Contains different structs and methods related to the Falcon DSA.
//!
//! It uses and acknowledges the work in:
//!
//! 1. The [reference](https://falcon-sign.info/impl/README.txt.html) implementation by Thomas
//!    Pornin.
//! 2. The Rust fn-dsa implementation by Thomas Pornin: https://github.com/pornin/rust-fn-dsa
//! 3. The [Rust](https://github.com/aszepieniec/falcon-rust) implementation by Alan Szepieniec in
//!    earlier versions of this crate.
use alloc::vec::Vec;
use core::ops::MulAssign;

use num::{One, Zero};

use super::MODULUS;

mod field;
pub use field::FalconFelt;

mod polynomial;
pub use polynomial::Polynomial;

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
