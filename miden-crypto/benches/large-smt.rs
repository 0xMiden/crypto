use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word,
    merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
};

mod common;
use common::*;

use crate::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE};

fn generate_test_keys(count: usize) -> Vec<Word> {
    (0..count)
        .map(|i| {
            Word::new([
                Felt::new(i as u64),
                Felt::new((i + 1) as u64),
                Felt::new((i + 2) as u64),
                Felt::new((i + 3) as u64),
            ])
        })
        .collect()
}

fn generate_smt_entries(count: usize) -> Vec<(Word, Word)> {
    (0..count)
        .map(|i| {
            let key = Word::new([
                Felt::new(i as u64),
                Felt::new((i + 1) as u64),
                Felt::new((i + 2) as u64),
                Felt::new((i + 3) as u64),
            ]);
            let value = Word::new([
                Felt::new((i + 4) as u64),
                Felt::new((i + 5) as u64),
                Felt::new((i + 6) as u64),
                Felt::new((i + 7) as u64),
            ]);
            (key, value)
        })
        .collect()
}

benchmark_with_setup_data! {
    large_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries(256);
        let keys = generate_test_keys(10);
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
        let entries = generate_smt_entries(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        let new_entries = generate_smt_entries(10_000);
        (smt, new_entries, temp_dir)
    },
    |b: &mut criterion::Bencher, (smt, new_entries, _temp_dir): &(LargeSmt<RocksDbStorage>, Vec<(Word, Word)>, tempfile::TempDir)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

benchmark_batch! {
    large_smt_apply_mutations,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, mutation_count: usize| {
        let base_entries = generate_smt_entries(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries).unwrap();

        b.iter(|| {
            for _ in 0..mutation_count {
                let new_entries = generate_smt_entries(10_000);
                let mutations = smt.compute_mutations(new_entries).unwrap();
                smt.apply_mutations(mutations).unwrap();
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
);

criterion_main!(large_smt_benchmark_group);
