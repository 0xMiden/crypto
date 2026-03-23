//! Shared development utilities for p3-miden crates.
//!
//! This crate provides:
//! - **Configurations**: Field/hash combinations (BabyBear+Poseidon2, etc.)
//! - **Benchmark utilities**: Criterion config, matrix generation
//! - **Test fixtures**: Seeds, matrix scenarios, constants
//!
//! # For Tests
//!
//! Import from a specific config module to get type aliases and constructors:
//!
//! ```ignore
//! use p3_miden_dev_utils::configs::baby_bear_poseidon2::*;
//!
//! #[test]
//! fn test_example() {
//!     let challenger = test_challenger();
//!     // F, EF, P, WIDTH, RATE, DIGEST are available
//! }
//! ```
//!
//! # For Benchmarks
//!
//! Use trait-based dispatch for generic benchmarks:
//!
//! ```ignore
//! use p3_miden_dev_utils::{
//!     BenchScenario, BabyBearPoseidon2, GoldilocksBlake3_192, GoldilocksPoseidon2,
//!     bench::criterion_config, fixtures::LOG_HEIGHTS,
//! };
//!
//! fn bench_generic<S: BenchScenario>(c: &mut Criterion) {
//!     let mmcs = S::packed_mmcs();
//!     // ...
//! }
//! ```

#![no_std]
extern crate alloc;

// =============================================================================
// Modules
// =============================================================================

#[cfg(not(target_arch = "wasm32"))]
pub mod bench;
pub mod configs;
pub mod fixtures;
pub mod matrix;

// =============================================================================
// Re-exports at crate root for convenience
// =============================================================================

// Traits
// Bench utilities (only on std targets)
#[cfg(not(target_arch = "wasm32"))]
pub use bench::{PARALLEL_STR, criterion_config, criterion_config_long};
// Scenario structs
pub use configs::{
    BabyBearBlake3_192, BabyBearKeccak, BabyBearPoseidon2, GoldilocksBlake3_192, GoldilocksKeccak,
    GoldilocksPoseidon2,
};
pub use configs::{BenchScenario, PcsScenario};
// Common fixtures
pub use fixtures::{BENCH_SEED, LOG_HEIGHTS, RELATIVE_SPECS, TEST_SEED};
// Matrix utilities
pub use matrix::{
    concatenate_matrices, generate_flat_matrix, generate_matrices_from_specs, random_lde_matrix,
    total_elements, total_elements_flat,
};
