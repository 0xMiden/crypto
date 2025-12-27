//! Optimized NTRU solver from rust-fn-dsa
//!
//! This module contains the optimized key generation algorithm from pornin's rust-fn-dsa
//! implementation. The code provides significant performance improvements over the standard
//! recursive approach through:
//! - Fixed-point arithmetic instead of arbitrary-precision integers
//! - Modular arithmetic with small primes (RNS representation)
//! - Optimized FFT-based polynomial operations
//! - Efficient Babai reduction
//!
//! Original source: https://github.com/pornin/rust-fn-dsa

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::module_inception)]

pub(crate) mod fxp;
pub(crate) mod mp31;
pub(crate) mod ntru;
pub(crate) mod poly;
pub(crate) mod vect;
pub(crate) mod zint31;

// Re-export key functions
pub(crate) use ntru::{check_ortho_norm, solve_NTRU};

// Note: gauss module is not included as we use miden-crypto's own polynomial sampling
