//! Comprehensive Sparse Merkle Tree (SMT) operation benchmarks
//!
//! This module benchmarks all public APIs of the SMT implementations
//! with a focus on tree creation, updates, proofs, and mutations.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Full SMT benchmarks (Smt struct)
//! 2. Simple SMT benchmarks (SimpleSmt const-generic)
//! 3. Proof verification benchmarks
//! 4. Mutation computation and application
//! 5. Batch operations
//!
//! # Benchmarking Strategy
//!
//! - Tree creation benchmarks use `benchmark_with_setup_data!` for efficient setup
//! - Multi-size benchmarks use `benchmark_multi!` for scalability testing
//! - Batch operations use `benchmark_batch!` for performance analysis
//!
//! # Adding New SMT Benchmarks
//!
//! To add benchmarks for new SMT operations:
//! 1. Add the operation to the appropriate benchmark group
//! 2. Follow naming conventions: `smt_<struct>_<operation>_<parameter>`
//! 3. Use the appropriate macro for benchmark type
//! 4. Update input size arrays if needed

use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word,
    merkle::{LeafIndex, SimpleSmt, Smt},
};

mod common;
use common::*;

// === Test Data Generation ===
use crate::data::generate_smt_entries_sequential as generate_smt_entries;
use crate::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{
        generate_simple_smt_entries_sequential as generate_simple_smt_entries,
        generate_test_keys_sequential as generate_test_keys,
    },
};

// === Full Smt Benchmarks ===

// Smt::new() tree creation
benchmark_with_setup! {
    smt_new,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "new",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _smt = Smt::new();
        })
    },
}

// Smt::with_entries() tree creation with initial data
benchmark_with_setup_data! {
    smt_with_entries,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "with_entries",
    || {
        generate_smt_entries(256)
    },
    |b: &mut criterion::Bencher, entries: &Vec<(Word, Word)>| {
        b.iter(|| {
            let _smt = Smt::with_entries(entries.clone()).unwrap();
        })
    },
}

// Smt root computation
benchmark_with_setup_data! {
    smt_root,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "root",
    || {
        let entries: Vec<(Word, Word)> = generate_smt_entries(256);
        Smt::with_entries(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &Smt| {
        b.iter(|| {
            hint::black_box(smt.root());
        })
    },
}

// Smt get_value operations
benchmark_with_setup_data! {
    smt_get_value,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "get_value",
    || {
        let entries = generate_smt_entries(256);
        let keys: Vec<Word> = generate_test_keys(100);
        let smt = Smt::with_entries(entries).unwrap();
        (smt, keys)
    },
    |b: &mut criterion::Bencher, (smt, keys): &(Smt, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.get_value(key));
            }
        })
    },
}

// Smt insert operations with multiple input sizes
benchmark_batch! {
    smt_insert,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(entries).unwrap();
        let new_key = Word::new([Felt::new(999), Felt::new(1000), Felt::new(1001), Felt::new(1002)]);
        let new_value = Word::new([Felt::new(1003), Felt::new(1004), Felt::new(1005), Felt::new(1006)]);

        b.iter(|| {
            for _ in 0..insert_count {
                smt.insert(new_key, new_value).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Smt open operations (proof generation)
benchmark_with_setup_data! {
    smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries(256);
        let keys = generate_test_keys(10);
        let smt = Smt::with_entries(entries).unwrap();
        (smt, keys)
    },
    |b: &mut criterion::Bencher, (smt, keys): &(Smt, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.open(key));
            }
        })
    },
}

// Smt num_leaves and num_entries accessors
benchmark_with_setup_data! {
    smt_counters,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "counters",
    || {
        let entries = generate_smt_entries(512);
        Smt::with_entries(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &Smt| {
        b.iter(|| {
            hint::black_box(smt.num_leaves());
            hint::black_box(smt.num_entries());
        })
    },
}

// Multi-size Smt tree creation
benchmark_multi! {
    smt_creation_sizes,
    "creation-sizes",
    &[16, 64, 256, 1024],
    |b: &mut criterion::Bencher, num_entries: &usize| {
        b.iter(|| {
            let entries: Vec<(Word, Word)> = (0..*num_entries)
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
                .collect();
            hint::black_box(Smt::with_entries(entries).unwrap());
        })
    }
}

// === SimpleSmt Benchmarks ===

// SimpleSmt::new() tree creation
benchmark_with_setup! {
    simple_smt_new,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "new",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _smt = SimpleSmt::<32>::new().unwrap();
        })
    },
}

// SimpleSmt::with_leaves() tree creation with initial data
benchmark_with_setup_data! {
    simple_smt_with_leaves,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "with_leaves",
    || {
        generate_simple_smt_entries(256)
    },
    |b: &mut criterion::Bencher, entries: &Vec<(u64, Word)>| {
        b.iter(|| {
            let _smt = SimpleSmt::<32>::with_leaves(entries.clone()).unwrap();
        })
    },
}

// SimpleSmt root computation
benchmark_with_setup_data! {
    simple_smt_root,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "root",
    || {
        let entries = generate_simple_smt_entries(256);
        SimpleSmt::<32>::with_leaves(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &SimpleSmt<32>| {
        b.iter(|| {
            hint::black_box(smt.root());
        })
    },
}

// SimpleSmt get_leaf operations
benchmark_with_setup_data! {
    simple_smt_get_leaf,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "get_leaf",
    || {
        let entries = generate_simple_smt_entries(256);
        let indices: Vec<LeafIndex<32>> = (0..100)
            .map(|i| LeafIndex::<32>::new(i).unwrap())
            .collect();
        let smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        (smt, indices)
    },
    |b: &mut criterion::Bencher, (smt, indices): &(SimpleSmt<32>, Vec<LeafIndex<32>>)| {
        b.iter(|| {
            for index in indices {
                hint::black_box(smt.get_leaf(index));
            }
        })
    },
}

// SimpleSmt insert operations with multiple input sizes
benchmark_batch! {
    simple_smt_insert,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let entries = generate_simple_smt_entries(256);
        let mut smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        let new_index = LeafIndex::<32>::new(999).unwrap();
        let new_value = Word::new([Felt::new(1000), Felt::new(1001), Felt::new(1002), Felt::new(1003)]);

        b.iter(|| {
            for _ in 0..insert_count {
                smt.insert(new_index, new_value);
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// SimpleSmt open operations
benchmark_with_setup_data! {
    simple_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_simple_smt_entries(256);
        let indices: Vec<LeafIndex<32>> = (0..10)
            .map(|i| LeafIndex::<32>::new(i).unwrap())
            .collect();
        let smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        (smt, indices)
    },
    |b: &mut criterion::Bencher, (smt, indices): &(SimpleSmt<32>, Vec<LeafIndex<32>>)| {
        b.iter(|| {
            for index in indices {
                hint::black_box(smt.open(index));
            }
        })
    },
}

// SimpleSmt leaves iteration
benchmark_with_setup_data! {
    simple_smt_leaves,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "leaves",
    || {
        let entries = generate_simple_smt_entries(256);
        SimpleSmt::<32>::with_leaves(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &SimpleSmt<32>| {
        b.iter(|| {
            let _count = smt.leaves().count();
        })
    },
}

// === Mutation Benchmarks ===

// Smt compute_mutations
benchmark_with_setup_data! {
    smt_compute_mutations,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compute_mutations",
    || {
        let entries = generate_smt_entries(256);
        let smt = Smt::with_entries(entries).unwrap();
        let new_entries = generate_smt_entries(32);
        (smt, new_entries)
    },
    |b: &mut criterion::Bencher, (smt, new_entries): &(Smt, Vec<(Word, Word)>)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

// Smt apply_mutations with multiple input sizes
benchmark_batch! {
    smt_apply_mutations,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, mutation_count: usize| {
        let base_entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(base_entries).unwrap();

        b.iter(|| {
            for _ in 0..mutation_count {
                let new_entries = generate_smt_entries(32);
                let mutations = smt.compute_mutations(new_entries).unwrap();
                smt.apply_mutations(mutations).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// === Batch Operations Benchmarks ===

// Batch Smt updates
benchmark_batch! {
    smt_batch_updates,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, update_count: usize| {
        let entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(entries).unwrap();
        let update_pairs: Vec<(Word, Word)> = (0..update_count)
            .map(|i| {
                let key = Word::new([
                    Felt::new((1000 + i) as u64),
                    Felt::new((1001 + i) as u64),
                    Felt::new((1002 + i) as u64),
                    Felt::new((1003 + i) as u64),
                ]);
                let value = Word::new([
                    Felt::new((1004 + i) as u64),
                    Felt::new((1005 + i) as u64),
                    Felt::new((1006 + i) as u64),
                    Felt::new((1007 + i) as u64),
                ]);
                (key, value)
            })
            .collect();

        b.iter(|| {
            for (key, value) in &update_pairs {
                smt.insert(*key, *value).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Batch SimpleSmt updates
benchmark_batch! {
    simple_smt_batch_updates,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, update_count: usize| {
        let entries = generate_simple_smt_entries(256);
        let mut smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        let updates: Vec<(LeafIndex<32>, Word)> = (0..update_count)
            .map(|i| {
                let index = LeafIndex::<32>::new(1000u64 + i as u64).unwrap();
                let value = Word::new([
                    Felt::new((1000 + i) as u64),
                    Felt::new((1001 + i) as u64),
                    Felt::new((1002 + i) as u64),
                    Felt::new((1003 + i) as u64),
                ]);
                (index, value)
            })
            .collect();

        b.iter(|| {
            for (index, value) in &updates {
                smt.insert(*index, *value);
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// === Benchmark Group Configuration ===

criterion_group!(
    smt_benchmark_group,
    // Full Smt benchmarks
    smt_new,
    smt_with_entries,
    smt_root,
    smt_get_value,
    smt_insert,
    smt_open,
    smt_counters,
    smt_creation_sizes,
    // SimpleSmt benchmarks
    simple_smt_new,
    simple_smt_with_leaves,
    simple_smt_root,
    simple_smt_get_leaf,
    simple_smt_insert,
    simple_smt_open,
    simple_smt_leaves,
    // Mutation benchmarks
    smt_compute_mutations,
    smt_apply_mutations,
    // Batch operations
    smt_batch_updates,
    simple_smt_batch_updates,
);

criterion_main!(smt_benchmark_group);
