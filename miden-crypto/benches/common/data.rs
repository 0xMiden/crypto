//! Data generation utilities for consistent benchmark inputs
//!
//! This module provides generic functions for generating test data
//! across all benchmark modules to ensure reproducible and consistent results.
//!
//! # Usage Pattern
//!
//! ```rust
//! use miden_crypto::{Felt, benches::common::data::*};
//!
//! // Generate test data using generic functions
//! let small_data = generate_byte_array_sequential(100);
//! let medium_data = generate_felt_array_sequential(1000);
//! let random_data = generate_byte_array_random(1024);
//! ```

use std::iter;

use miden_crypto::{Felt, ONE, Word};
use rand_utils::{prng_array, rand_value};

// === Byte Array Generation ===

/// Generate byte array of specified size with sequential data
pub fn generate_byte_array_sequential(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

/// Generate byte array of specified size with random data
pub fn generate_byte_array_random(size: usize) -> Vec<u8> {
    iter::from_fn(|| Some(rand_value::<u8>())).take(size).collect()
}

// === Field Element Generation ===

/// Generate field element array with sequential values
pub fn generate_felt_array_sequential(size: usize) -> Vec<Felt> {
    (0..size).map(|i| Felt::new(i as u64)).collect()
}

/// Generate byte array of specified size with random data
pub fn generate_felt_array_random(size: usize) -> Vec<Felt> {
    iter::from_fn(|| Some(Felt::new(rand_value::<u64>()))).take(size).collect()
}

// === Word and Value Generation ===

/// Generate a Word from seed using PRNG
pub fn generate_word(seed: &mut [u8; 32]) -> Word {
    *seed = prng_array(*seed);
    let nums: [u64; 4] = prng_array(*seed);
    Word::new([Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])])
}

/// Generate a generic value from seed using PRNG
pub fn generate_value<T: winter_utils::Randomizable + std::fmt::Debug + Clone>(
    seed: &mut [u8; 32],
) -> T {
    *seed = prng_array(*seed);
    let value: [T; 1] = rand_utils::prng_array(*seed);
    value[0].clone()
}

/// Prepare key-value entries for SMT benchmarks
pub fn prepare_smt_entries(pair_count: u64, seed: &mut [u8; 32]) -> Vec<(Word, Word)> {
    let entries: Vec<(Word, Word)> = (0..pair_count)
        .map(|i| {
            let count = pair_count as f64;
            let idx = ((i as f64 / count) * (count)) as u64;
            let key = Word::new([generate_value(seed), ONE, Felt::new(i), Felt::new(idx)]);
            let value = generate_word(seed);
            (key, value)
        })
        .collect();
    entries
}

/// Generate test key-value pairs for SMT benchmarks (sequential)
pub fn generate_smt_entries_sequential(count: usize) -> Vec<(Word, Word)> {
    (0..count)
        .map(|i| {
            let key = Word::new([
                Felt::new(i as u64),
                Felt::new((i + 1) as u64),
                Felt::new((i + 2) as u64),
                Felt::new((i + 3) as u64),
            ]);
            let value = Word::new([
                Felt::new((i + 4) as u64),
                Felt::new((i + 5) as u64),
                Felt::new((i + 6) as u64),
                Felt::new((i + 7) as u64),
            ]);
            (key, value)
        })
        .collect()
}

/// Generate test entries for SimpleSmt benchmarks (sequential)
pub fn generate_simple_smt_entries_sequential(count: usize) -> Vec<(u64, Word)> {
    (0..count)
        .map(|i| {
            let key = i as u64;
            let value = Word::new([
                Felt::new(i as u64),
                Felt::new((i + 1) as u64),
                Felt::new((i + 2) as u64),
                Felt::new((i + 3) as u64),
            ]);
            (key, value)
        })
        .collect()
}

/// Generate test keys for lookup operations (sequential)
pub fn generate_test_keys_sequential(count: usize) -> Vec<Word> {
    (0..count)
        .map(|i| {
            Word::new([
                Felt::new(i as u64),
                Felt::new((i + 1) as u64),
                Felt::new((i + 2) as u64),
                Felt::new((i + 3) as u64),
            ])
        })
        .collect()
}
