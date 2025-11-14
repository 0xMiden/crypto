use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
};

mod common;
use common::*;

use crate::{
    common::data::{generate_smt_entries_sequential, generate_test_keys_sequential},
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
};

benchmark_with_setup_data! {
    large_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries_sequential(256);
        let keys = generate_test_keys_sequential(10);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        (smt, keys, temp_dir)
    },
    |b: &mut criterion::Bencher, (smt, keys, _temp_dir): &(LargeSmt<RocksDbStorage>, Vec<Word>, tempfile::TempDir)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.open(key));
            }
        })
    },
}

benchmark_with_setup_data! {
    large_smt_compute_mutations,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compute_mutations",
    || {
        let entries = generate_smt_entries_sequential(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        let new_entries = generate_smt_entries_sequential(10_000);
        (smt, new_entries, temp_dir)
    },
    |b: &mut criterion::Bencher, (smt, new_entries, _temp_dir): &(LargeSmt<RocksDbStorage>, Vec<(Word, Word)>, tempfile::TempDir)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

// Benchmarks apply_mutations at different batch sizes.
// Setup: Creates fresh tree and computes mutations
// Measured: Only the apply_mutations call
// Tests: Performance scaling with mutation size (100, 1k, 10k entries) on a tree with 256 entries
benchmark_batch! {
    large_smt_apply_mutations,
    &[100, 1_000, 10_000],
    |b: &mut criterion::Bencher, entry_count: usize| {
        use criterion::BatchSize;

        let base_entries = generate_smt_entries_sequential(256);
        let bench_dir = std::env::temp_dir().join("bench_apply_mutations");

        b.iter_batched(
            || {
                std::fs::create_dir_all(&bench_dir).unwrap();
                let storage = RocksDbStorage::open(RocksDbConfig::new(&bench_dir)).unwrap();
                let smt = LargeSmt::with_entries(storage, base_entries.clone()).unwrap();
                let new_entries = generate_smt_entries_sequential(entry_count);
                let mutations = smt.compute_mutations(new_entries).unwrap();

                (smt, mutations, bench_dir.clone())
            },
            |(mut smt, mutations, bench_dir)| {
                smt.apply_mutations(mutations).unwrap();
                drop(smt);
                let _ = std::fs::remove_dir_all(&bench_dir);
            },
            BatchSize::LargeInput,
        )
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Benchmarks apply_mutations_with_reversion at different batch sizes.
// Setup: Creates fresh tree and computes mutations
// Measured: Only the apply_mutations_with_reversion call
// Tests: Performance scaling with mutation size (100, 1k, 10k entries) on a tree with 256 entries
benchmark_batch! {
    large_smt_apply_mutations_with_reversion,
    &[100, 1_000, 10_000],
    |b: &mut criterion::Bencher, entry_count: usize| {
        use criterion::BatchSize;

        let base_entries = generate_smt_entries_sequential(256);
        let bench_dir = std::env::temp_dir().join("bench_apply_mutations_with_reversion");

        b.iter_batched(
            || {
                std::fs::create_dir_all(&bench_dir).unwrap();
                let storage = RocksDbStorage::open(RocksDbConfig::new(&bench_dir)).unwrap();
                let smt = LargeSmt::with_entries(storage, base_entries.clone()).unwrap();
                let new_entries = generate_smt_entries_sequential(entry_count);
                let mutations = smt.compute_mutations(new_entries).unwrap();

                (smt, mutations, bench_dir.clone())
            },
            |(mut smt, mutations, bench_dir)| {
                let _ = smt.apply_mutations_with_reversion(mutations).unwrap();
                drop(smt);
                let _ = std::fs::remove_dir_all(&bench_dir);
            },
            BatchSize::LargeInput,
        )
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

benchmark_batch! {
    large_smt_insert_batch,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let base_entries = generate_smt_entries_sequential(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries).unwrap();

        b.iter(|| {
            for _ in 0..insert_count {
                let new_entries = generate_smt_entries_sequential(10_000);
                smt.insert_batch(new_entries).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

criterion_group!(
    large_smt_benchmark_group,
    large_smt_open,
    large_smt_compute_mutations,
    large_smt_apply_mutations,
    large_smt_apply_mutations_with_reversion,
    large_smt_insert_batch,
);

criterion_main!(large_smt_benchmark_group);
