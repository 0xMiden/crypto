//! Test and benchmark fixtures (constants, scenarios).
//!
//! This module contains constants and helper functions that define
//! reproducible test/benchmark scenarios.

// =============================================================================
// Seeds
// =============================================================================

/// Standard seed for reproducible tests/benchmarks.
pub const TEST_SEED: u64 = 2025;

/// Alias for benchmark seed (same value as TEST_SEED).
pub const BENCH_SEED: u64 = TEST_SEED;

// =============================================================================
// Benchmark constants
// =============================================================================

/// Standard log heights for benchmarking: 2^16, 2^18, 2^20 leaves.
pub const LOG_HEIGHTS: &[u8] = &[16, 18, 20];

/// Standard relative specs for benchmark matrix groups.
///
/// Each inner slice is a separate commitment group.
/// Tuple format: `(offset_from_max, width)` where `log_height = log_max_height - offset`.
///
/// This gives realistic matrix configurations similar to STARK traces:
/// - Group 0: Main trace columns at various heights
/// - Group 1: Auxiliary/permutation columns
/// - Group 2: Quotient polynomial chunks
pub const RELATIVE_SPECS: &[&[(usize, usize)]] = &[
    &[(4, 10), (2, 100), (0, 50)],
    &[(4, 8), (2, 20), (0, 20)],
    &[(0, 16)],
];
