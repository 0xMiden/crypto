//! A unified `Felt` for Miden Rust code.
//!
//! This crate provides a single `Felt` type that can be used in both:
//! - On-chain (Wasm + `miden`): `Felt` is backed by a Miden VM felt via compiler intrinsics.
//! - Off-chain (native / non-Miden Wasm): `Felt` is backed by Plonky3's Goldilocks field element.

#![no_std]
#![deny(warnings)]

extern crate alloc;

/// The field modulus, `2^64 - 2^32 + 1`.
pub const MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Errors returned by [`Felt::new_checked`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FeltError {
    /// The provided value was not a valid canonical felt.
    InvalidValue,
}

#[cfg(all(target_family = "wasm", miden))]
mod wasm_miden;
#[cfg(all(target_family = "wasm", miden))]
pub use wasm_miden::Felt;

#[cfg(not(all(target_family = "wasm", miden)))]
mod native;
#[cfg(not(all(target_family = "wasm", miden)))]
pub use native::Felt;

impl Felt {
    /// Field modulus = 2^64 - 2^32 + 1.
    pub const M: u64 = MODULUS;

    /// The order of the field.
    pub const ORDER_U64: u64 = MODULUS;

    /// The serialized size of a felt in bytes.
    pub const NUM_BYTES: usize = core::mem::size_of::<u64>();

    /// Creates a `Felt` from a `u8` value.
    #[inline(always)]
    pub fn from_u8(value: u8) -> Self {
        Self::new(value as u64)
    }

    /// Creates a `Felt` from a `u16` value.
    #[inline(always)]
    pub fn from_u16(value: u16) -> Self {
        Self::new(value as u64)
    }

    /// Creates a `Felt` from a `u32` value.
    #[inline(always)]
    pub fn from_u32(value: u32) -> Self {
        Self::new(value as u64)
    }

    /// Creates a `Felt` from a `u64` value.
    ///
    /// This is equivalent to [`Felt::new`].
    #[inline(always)]
    pub fn from_u64(value: u64) -> Self {
        Self::new(value)
    }

    /// Creates a `Felt` from `value`, returning an error if it is out of range.
    ///
    /// For canonical values in the range `[0, MODULUS)`, prefer [`Felt::from_canonical_checked`].
    #[inline]
    pub fn new_checked(value: u64) -> Result<Self, FeltError> {
        Self::from_canonical_checked(value).ok_or(FeltError::InvalidValue)
    }

    /// Creates a `Felt` from a canonical `u64` value.
    ///
    /// Returns `None` if `value >= MODULUS`.
    #[inline]
    pub fn from_canonical_checked(value: u64) -> Option<Self> {
        (value < MODULUS).then(|| Self::new(value))
    }
}
