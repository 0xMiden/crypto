//! Test and benchmark utilities for generating random data.
//!
//! This module provides helper functions for tests and benchmarks that need
//! random data generation. These functions replace the functionality previously
//! provided by winter-rand-utils.

use alloc::vec::Vec;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::rand::Randomizable;

/// Generates a random value of type T using the thread-local random number generator.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_value;
/// let x: u64 = rand_value();
/// let y: u128 = rand_value();
/// ```
#[cfg(feature = "std")]
pub fn rand_value<T: Randomizable>() -> T {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; T::VALUE_SIZE];
    rng.fill(&mut bytes[..]);
    T::from_random_bytes(&bytes).expect("failed to generate random value")
}

/// Generates a random array of type T with N elements.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_array;
/// let arr: [u64; 4] = rand_array();
/// ```
#[cfg(feature = "std")]
pub fn rand_array<T: Randomizable, const N: usize>() -> [T; N] {
    core::array::from_fn(|_| rand_value())
}

/// Generates a random vector of type T with the specified length.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_vector;
/// let vec: Vec<u64> = rand_vector(100);
/// ```
#[cfg(feature = "std")]
pub fn rand_vector<T: Randomizable>(length: usize) -> Vec<T> {
    (0..length).map(|_| rand_value()).collect()
}

/// Generates a deterministic array using a PRNG seeded with the provided seed.
///
/// This function uses ChaCha20 PRNG for deterministic random generation, which is
/// useful for reproducible tests and benchmarks.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::prng_array;
/// let seed = [0u8; 32];
/// let arr: [u64; 4] = prng_array(seed);
/// ```
pub fn prng_array<T: Randomizable, const N: usize>(seed: [u8; 32]) -> [T; N] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    core::array::from_fn(|_| {
        let mut bytes = vec![0u8; T::VALUE_SIZE];
        rng.fill(&mut bytes[..]);
        T::from_random_bytes(&bytes).expect("failed to generate random value")
    })
}

/// Generates a deterministic vector using a PRNG seeded with the provided seed.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::prng_vector;
/// let seed = [0u8; 32];
/// let vec: Vec<u64> = prng_vector(seed, 100);
/// ```
pub fn prng_vector<T: Randomizable>(seed: [u8; 32], length: usize) -> Vec<T> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    (0..length)
        .map(|_| {
            let mut bytes = vec![0u8; T::VALUE_SIZE];
            rng.fill(&mut bytes[..]);
            T::from_random_bytes(&bytes).expect("failed to generate random value")
        })
        .collect()
}
