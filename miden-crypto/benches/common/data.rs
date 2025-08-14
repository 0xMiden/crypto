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

use miden_crypto::Felt;
use rand_utils::rand_value;

// === Byte Array Generation ===

/// Generate byte array of specified size with sequential data
pub fn generate_byte_array_sequential(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

/// Generate byte array of specified size with random data
pub fn generate_byte_array_random(size: usize) -> Vec<u8> {
    let mut result = vec![0u8; size];
    for i in 0..size {
        result[i] = rand_value::<u8>();
    }
    result
}

// === Field Element Generation ===

/// Generate field element array with sequential values
pub fn generate_felt_array_sequential(size: usize) -> Vec<Felt> {
    (0..size).map(|i| Felt::new(i as u64)).collect()
}
