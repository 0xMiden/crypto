//! Shared development utilities for p3-miden crates.
//!
//! This crate provides:
//! - **Configurations**: Field/hash combinations (Goldilocks+Poseidon2, Goldilocks+Keccak)
//! - **Test fixtures**: Seeds, matrix scenarios, constants
//! - **Matrix utilities**: Matrix generation for benchmarks and tests
//!
//! # Usage
//!
//! Import from a specific config module to get type aliases and constructors:
//!
//! ```ignore
//! use p3_miden_dev_utils::configs::goldilocks_poseidon2::*;
//!
//! #[test]
//! fn test_example() {
//!     let challenger = test_challenger();
//!     // F, EF, P, WIDTH, RATE, DIGEST are available
//! }
//! ```

#![no_std]
extern crate alloc;

// =============================================================================
// Modules
// =============================================================================

pub mod configs;
pub mod fixtures;
pub mod matrix;

// =============================================================================
// Re-exports at crate root for convenience
// =============================================================================

// Common fixtures
pub use fixtures::{BENCH_SEED, LOG_HEIGHTS, RELATIVE_SPECS, TEST_SEED};
// Matrix utilities
pub use matrix::{generate_matrices_from_specs, total_elements};
