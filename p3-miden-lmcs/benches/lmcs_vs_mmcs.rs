//! LMCS vs MMCS comparison benchmarks.
//!
//! Compares the lifted LMCS implementation against the workspace MerkleTreeMmcs
//! using identical hash configurations. Runs benchmarks for:
//! - Goldilocks + Poseidon2
//! - Goldilocks + Keccak
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench lmcs_vs_mmcs --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench lmcs_vs_mmcs --features testing,parallel
//!
//! # Filter by field/hash
//! cargo bench --bench lmcs_vs_mmcs --features testing -- goldilocks/poseidon2
//! cargo bench --bench lmcs_vs_mmcs --features testing -- keccak
//! ```

mod utils;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p3_commit::Mmcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_miden_dev_utils::{
    LOG_HEIGHTS, RELATIVE_SPECS, configs::goldilocks_poseidon2::F, generate_matrices_from_specs,
    total_elements,
};
use p3_miden_lmcs::{Lmcs, LmcsTree};

const PARALLEL_STR: &str = if cfg!(feature = "parallel") {
    "parallel"
} else {
    "single"
};

// =============================================================================
// Benchmark implementation
// =============================================================================

/// Run benchmark for a specific hash configuration.
fn bench_hash<L: Lmcs<F = F>, M: Mmcs<F>>(c: &mut Criterion, lmcs: &L, mmcs: &M, hash_name: &str) {
    for &log_max_height in LOG_HEIGHTS {
        let n_leaves = 1usize << log_max_height;
        let group_name = format!(
            "LMCS_vs_MMCS/{}/goldilocks/{}/{}",
            n_leaves, hash_name, PARALLEL_STR
        );
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(total_elements(
            &generate_matrices_from_specs::<F>(RELATIVE_SPECS, log_max_height),
        )));

        // Generate matrices using canonical specs
        let matrix_groups: Vec<Vec<RowMajorMatrix<F>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_max_height);

        // LMCS (using Lmcs trait API)
        group.bench_with_input(
            BenchmarkId::from_parameter("lmcs"),
            &matrix_groups,
            |b, groups| {
                b.iter(|| {
                    for matrices in groups {
                        let tree = lmcs.build_tree(matrices.clone());
                        black_box(tree.root());
                    }
                });
            },
        );

        // MMCS
        group.bench_with_input(
            BenchmarkId::from_parameter("mmcs"),
            &matrix_groups,
            |b, groups| {
                b.iter(|| {
                    for matrices in groups {
                        black_box(mmcs.commit(matrices.clone()));
                    }
                });
            },
        );

        group.finish();
    }
}

fn bench_lmcs_vs_mmcs(c: &mut Criterion) {
    use p3_miden_lmcs::testing::goldilocks_poseidon2::test_lmcs;
    use utils::*;

    // Poseidon2 scenario
    bench_hash(c, &test_lmcs(), &gl_poseidon2_mmcs(), "poseidon2");

    // Keccak scenario
    bench_hash(c, &gl_keccak_lmcs(), &gl_keccak_mmcs(), "keccak");
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_lmcs_vs_mmcs
}
criterion_main!(benches);
