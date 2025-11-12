#![cfg(all(feature = "rocksdb", feature = "std"))]

use std::hint;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{EmptySubtreeRoots, PersistedSmtForest, RocksDbForestConfig, SMT_DEPTH},
};
use tempfile::TempDir;

mod common;
use common::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{generate_smt_entries_mixed, generate_smt_entries_sequential},
};

struct PersistedForestOpenContext {
    temp_dir: TempDir,
    forest: PersistedSmtForest,
    root: Word,
    keys: Vec<Word>,
}

struct PersistedForestBatchContext {
    temp_dir: TempDir,
    forest: PersistedSmtForest,
    base_root: Word,
    entries: Vec<(Word, Word)>,
}

benchmark_with_setup_data! {
    persisted_smt_forest_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "persisted-forest-open",
    || {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config = RocksDbForestConfig::new(temp_dir.path());
        let mut forest = PersistedSmtForest::new(config).expect("create persisted forest");

        let base_entries = generate_smt_entries_sequential(256);
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        let populated_root = forest.batch_insert(empty_root, base_entries.clone()).unwrap();
        let keys = base_entries.iter().map(|(key, _)| *key).collect();

        PersistedForestOpenContext {
            temp_dir,
            forest,
            root: populated_root,
            keys,
        }
    },
    |b: &mut criterion::Bencher, ctx: &PersistedForestOpenContext| {
        b.iter(|| {
            for key in &ctx.keys {
                let _ = hint::black_box(ctx.forest.open(ctx.root, *key));
            }
        })
    },
}

benchmark_batch! {
    persisted_smt_forest_batch_insert,
    &[1, 16, 256, 1_024],
    |b: &mut criterion::Bencher, entry_count: usize| {
        b.iter_batched(
            || {
                let temp_dir = tempfile::tempdir().expect("tempdir");
                let config = RocksDbForestConfig::new(temp_dir.path());
                let mut forest = PersistedSmtForest::new(config).expect("create persisted forest");

                let base_entries = generate_smt_entries_sequential(256);
                let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
                let base_root = forest.batch_insert(empty_root, base_entries.clone()).unwrap();
                let entries = generate_smt_entries_mixed(entry_count);

                PersistedForestBatchContext {
                    temp_dir,
                    forest,
                    base_root,
                    entries,
                }
            },
            |ctx: PersistedForestBatchContext| {
                let PersistedForestBatchContext { mut forest, base_root, entries, temp_dir } = ctx;
                hint::black_box(forest.batch_insert(base_root, entries).unwrap());
                drop(forest);
                drop(temp_dir);
            },
            BatchSize::LargeInput,
        );
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

criterion_group!(
    persisted_smt_forest_benches,
    persisted_smt_forest_open,
    persisted_smt_forest_batch_insert,
);

criterion_main!(persisted_smt_forest_benches);
