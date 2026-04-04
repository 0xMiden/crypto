//! FRI fold comparison: workspace vs lifted (arity-2 only).
//!
//! Compares the workspace `TwoAdicFriFolding` implementation against the lifted
//! `FriFold` implementation for arity-2 folding. This provides an apples-to-apples
//! comparison of the two approaches. Field-only (no hash functions involved).
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench fri_comparison --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench fri_comparison --features testing,parallel
//!
//! # Filter by field
//! cargo bench --bench fri_comparison --features testing -- goldilocks
//! ```

use core::marker::PhantomData;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_matrix::dense::RowMajorMatrix;
use p3_miden_dev_utils::{
    BENCH_SEED, LOG_HEIGHTS,
    configs::goldilocks_poseidon2::{EF, F},
};
use p3_miden_lifted_fri::fri::FriFold;
use rand::{RngExt, SeedableRng, distr::StandardUniform, rngs::SmallRng};

const PARALLEL_STR: &str = if cfg!(feature = "parallel") {
    "parallel"
} else {
    "single"
};

fn bench_fri_comparison(c: &mut Criterion) {
    for &log_height in LOG_HEIGHTS {
        let n = 1usize << log_height;
        let group_name = format!("FRI_Fold_Arity2/{}/goldilocks/{}", n, PARALLEL_STR);
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(n as u64));

        // Setup (shared between implementations)
        let mut rng = SmallRng::seed_from_u64(BENCH_SEED);
        let beta: EF = rng.sample(StandardUniform);

        // Generate matrix with width=2 (arity-2)
        let values: Vec<EF> = (0..n * 2).map(|_| rng.sample(StandardUniform)).collect();
        let mat = RowMajorMatrix::new(values, 2);

        // Workspace benchmark - TwoAdicFriFolding computes domain points internally
        let workspace_folding = TwoAdicFriFolding::<(), ()>(PhantomData);
        group.bench_function(BenchmarkId::from_parameter("workspace"), |b| {
            b.iter(|| {
                <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_matrix(
                    &workspace_folding,
                    black_box(beta),
                    1,
                    black_box(mat.clone()),
                )
            });
        });

        // Lifted benchmark - FriFold requires precomputed s_inv values
        let s_invs: Vec<F> = (0..n).map(|_| rng.sample(StandardUniform)).collect();
        let lifted_fold = FriFold::ARITY_2;
        group.bench_function(BenchmarkId::from_parameter("lifted"), |b| {
            b.iter(|| {
                lifted_fold.fold_matrix(
                    black_box(mat.as_view()),
                    black_box(&s_invs),
                    black_box(beta),
                )
            });
        });

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_fri_comparison
}
criterion_main!(benches);
