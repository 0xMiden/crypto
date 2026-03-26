//! Merkle tree commit benchmarks for LMCS.
//!
//! Benchmarks LMCS commit operations including ExtensionMmcs for FRI.
//! Runs benchmarks for Goldilocks with Poseidon2.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench merkle_commit --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench merkle_commit --features testing,parallel
//!
//! # Filter by field
//! cargo bench --bench merkle_commit --features testing -- goldilocks
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p3_matrix::{bitrev::BitReversalPerm, dense::RowMajorMatrix, extension::FlatMatrixView};
use p3_miden_dev_utils::{
    LOG_HEIGHTS, RELATIVE_SPECS,
    configs::goldilocks_poseidon2::{EF, F},
    generate_matrices_from_specs, total_elements,
};
use p3_miden_lmcs::{Lmcs, LmcsTree, testing::goldilocks_poseidon2::test_lmcs};
use rand::{SeedableRng, rngs::SmallRng};

const PARALLEL_STR: &str = if cfg!(feature = "parallel") {
    "parallel"
} else {
    "single"
};

// =============================================================================
// Benchmark implementation
// =============================================================================

fn bench_merkle_commit(c: &mut Criterion) {
    let lmcs = test_lmcs();

    for &log_max_height in LOG_HEIGHTS {
        let n_leaves = 1usize << log_max_height;
        let group_name = format!(
            "MerkleCommit/{}/goldilocks/poseidon2/{}",
            n_leaves, PARALLEL_STR
        );
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(total_elements(
            &generate_matrices_from_specs::<F>(RELATIVE_SPECS, log_max_height),
        )));

        // Generate matrices using canonical specs
        let matrix_groups: Vec<Vec<RowMajorMatrix<F>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_max_height);

        // LMCS commit
        {
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
        }

        // Extension field matrix with width-2 (simulates FRI arity-2 commit)
        // Uses FlatMatrixView to convert EF matrix to base field view
        {
            let rng = &mut SmallRng::seed_from_u64(p3_miden_dev_utils::BENCH_SEED);
            let ext_matrix = RowMajorMatrix::<EF>::rand(rng, n_leaves, 2);

            group.bench_with_input(
                BenchmarkId::from_parameter("ext/arity2"),
                &ext_matrix,
                |b, matrix| {
                    b.iter(|| {
                        let flat = FlatMatrixView::new(matrix.clone());
                        let tree = lmcs.build_tree(vec![BitReversalPerm::new_view(flat)]);
                        black_box(tree.root())
                    });
                },
            );
        }

        // Extension field matrix with width-4 (simulates FRI arity-4 commit)
        {
            let rng = &mut SmallRng::seed_from_u64(p3_miden_dev_utils::BENCH_SEED);
            let ext_matrix = RowMajorMatrix::<EF>::rand(rng, n_leaves, 4);

            group.bench_with_input(
                BenchmarkId::from_parameter("ext/arity4"),
                &ext_matrix,
                |b, matrix| {
                    b.iter(|| {
                        let flat = FlatMatrixView::new(matrix.clone());
                        let tree = lmcs.build_tree(vec![BitReversalPerm::new_view(flat)]);
                        black_box(tree.root())
                    });
                },
            );
        }

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_merkle_commit
}
criterion_main!(benches);
