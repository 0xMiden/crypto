use std::{hint, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::merkle::Smt;

mod common;
use common::data::*;

// 2^0, 2^4, 2^8, 2^12, 2^16
const PAIR_COUNTS: [u64; 6] = [1, 16, 256, 4096, 65536, 1_048_576];

fn smt_with_entries(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("smt-with-entries");

    for pair_count in PAIR_COUNTS {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    prepare_smt_entries(pair_count, &mut seed)
                },
                |entries| {
                    // Benchmarked function.
                    Smt::with_entries(hint::black_box(entries)).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = smt_with_entries_group;
    config = Criterion::default()
        //.measurement_time(Duration::from_secs(960))
        .measurement_time(Duration::from_secs(60))
        .sample_size(10)
        .configure_from_args();
    targets = smt_with_entries
}
criterion_main!(smt_with_entries_group);

// HELPER FUNCTIONS
// === Helper Functions ===
