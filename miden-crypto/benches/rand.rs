//! Comprehensive random number generation benchmarks
//!
//! This module benchmarks all random number generation operations implemented in the library
//! with a focus on RPO and RPX-based random coins.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Random coin initialization using benchmark_rand_new!
//! 2. Element drawing operations using benchmark_rand_draw!
//! 3. Word drawing operations using benchmark_rand_draw!
//! 4. Reseeding operations using benchmark_rand_reseed!
//! 5. Integer drawing operations using benchmark_rand_draw_integers!
//! 6. Leading zero checking using benchmark_rand_check_leading_zeros!
//! 7. Byte filling operations using benchmark_rand_fill_bytes!
//!
//! # Adding New Random Benchmarks
//!
//! To add benchmarks for new random number generators:
//! 1. Add the algorithm to the imports
//! 2. Use benchmark_rand_comprehensive! for complete coverage
//! 3. Add to the appropriate benchmark group
//! 4. Update input size arrays in config.rs if needed

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
// Import random generation modules
use miden_crypto::{
    Felt, Word,
    rand::{FeltRng, RandomCoin, RpoRandomCoin, RpxRandomCoin},
};

// Import common utilities
mod common;
use common::*;

// Import configuration constants
use crate::config::PRNG_OUTPUT_SIZES;

/// Configuration for random coin testing
const TEST_SEED: Word = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);

// === RPO Random Coin Benchmarks ===

// Use individual macros for better control
benchmark_rand_new!(rand_rpo_new, RpoRandomCoin, TEST_SEED);
benchmark_rand_draw!(
    rand_rpo_draw_elements,
    RpoRandomCoin,
    TEST_SEED,
    "draw_element",
    PRNG_OUTPUT_SIZES,
    |coin: &mut RpoRandomCoin, count| {
        for _ in 0..count {
            let _element = coin.draw_element();
        }
    }
);
benchmark_rand_draw!(
    rand_rpo_draw_words,
    RpoRandomCoin,
    TEST_SEED,
    "draw_word",
    PRNG_OUTPUT_SIZES,
    |coin: &mut RpoRandomCoin, count| {
        for _ in 0..count {
            let _word = coin.draw_word();
        }
    }
);
benchmark_rand_reseed!(rand_rpo_reseed, RpoRandomCoin, TEST_SEED);
benchmark_rand_draw_integers!(rand_rpo_draw_integers, RpoRandomCoin, TEST_SEED);
benchmark_rand_check_leading_zeros!(rand_rpo_check_leading_zeros, RpoRandomCoin, TEST_SEED);
benchmark_rand_fill_bytes!(
    rand_rpo_fill_bytes,
    RpoRandomCoin,
    TEST_SEED,
    &[1, 32, 64, 128, 256, 512, 1024]
);

// === RPX Random Coin Benchmarks ===

// Use individual macros for better control
benchmark_rand_new!(rand_rpx_new, RpxRandomCoin, TEST_SEED);
benchmark_rand_draw!(
    rand_rpx_draw_elements,
    RpxRandomCoin,
    TEST_SEED,
    "draw_element",
    PRNG_OUTPUT_SIZES,
    |coin: &mut RpxRandomCoin, count| {
        for _ in 0..count {
            let _element = coin.draw_element();
        }
    }
);
benchmark_rand_draw!(
    rand_rpx_draw_words,
    RpxRandomCoin,
    TEST_SEED,
    "draw_word",
    PRNG_OUTPUT_SIZES,
    |coin: &mut RpxRandomCoin, count| {
        for _ in 0..count {
            let _word = coin.draw_word();
        }
    }
);
benchmark_rand_reseed!(rand_rpx_reseed, RpxRandomCoin, TEST_SEED);
benchmark_rand_draw_integers!(rand_rpx_draw_integers, RpxRandomCoin, TEST_SEED);
benchmark_rand_check_leading_zeros!(rand_rpx_check_leading_zeros, RpxRandomCoin, TEST_SEED);
benchmark_rand_fill_bytes!(
    rand_rpx_fill_bytes,
    RpxRandomCoin,
    TEST_SEED,
    &[1, 32, 64, 128, 256, 512, 1024]
);

// === Benchmark Group Configuration ===

criterion_group!(
    rand_benchmark_group,
    // RPO Random Coin benchmarks
    rand_rpo_new,
    rand_rpo_draw_elements,
    rand_rpo_draw_words,
    rand_rpo_reseed,
    rand_rpo_draw_integers,
    rand_rpo_check_leading_zeros,
    rand_rpo_fill_bytes,
    // RPX Random Coin benchmarks
    rand_rpx_new,
    rand_rpx_draw_elements,
    rand_rpx_draw_words,
    rand_rpx_reseed,
    rand_rpx_draw_integers,
    rand_rpx_check_leading_zeros,
    rand_rpx_fill_bytes,
);

criterion_main!(rand_benchmark_group);
