use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{EmptySubtreeRoots, SMT_DEPTH, SmtForest},
};

mod common;
use common::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{generate_smt_entries_mixed, generate_smt_entries_sequential},
};

benchmark_with_setup_data! {
    smt_forest_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "forest-open",
    || {
        let base_entries = generate_smt_entries_sequential(256);
        let mut forest = SmtForest::new();
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        let populated_root = forest.batch_insert(empty_root, base_entries.clone()).unwrap();
        let keys: Vec<Word> = base_entries.iter().map(|(key, _)| *key).collect();

        (forest, populated_root, keys)
    },
    |b: &mut criterion::Bencher, (forest, root, keys): &(SmtForest, Word, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                let _ = hint::black_box(forest.open(*root, *key));
            }
        })
    },
}

benchmark_batch! {
    smt_forest_batch_insert,
    &[1, 16, 256, 1_024],
    |b: &mut criterion::Bencher, entry_count: usize| {
        use criterion::BatchSize;

        let mut base_forest = SmtForest::new();
        let base_entries = generate_smt_entries_sequential(256);
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        let base_root = base_forest.batch_insert(empty_root, base_entries.clone()).unwrap();

        b.iter_batched(
            || {
                let forest = base_forest.clone();
                let entries = generate_smt_entries_mixed(entry_count);
                (forest, base_root, entries)
            },
            |(mut forest, root, entries)| {
                hint::black_box(forest.batch_insert(root, entries.clone()).unwrap());
            },
            BatchSize::LargeInput,
        );
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

criterion_group!(smt_forest_benches, smt_forest_open, smt_forest_batch_insert,);

criterion_main!(smt_forest_benches);
