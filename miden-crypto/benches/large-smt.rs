use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, FieldElement, Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{
            InnerNode, LargeSmt, MemoryStorage, RocksDbConfig, RocksDbStorage, SMT_DEPTH, Subtree,
        },
    },
};

mod common;
use common::*;

use crate::{
    common::data::{generate_smt_entries_sequential, generate_test_keys_sequential},
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
};

// === Subtree Serialization Benchmarks ===

const ROOT_DEPTH: u8 = 24;
const SUBTREE_DEPTH: u8 = 8;

// Creates a dense subtree with all inner nodes populated (bottom-up by depth).
fn create_dense_subtree() -> Subtree {
    let root_index = NodeIndex::new(ROOT_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(root_index);
    let node_hash: Word = [Felt::ONE; 4].into();

    for relative_depth in (1..=SUBTREE_DEPTH).rev() {
        let depth = ROOT_DEPTH + relative_depth;
        let nodes_at_depth = 1u64 << (relative_depth - 1);
        let first_value = nodes_at_depth;

        for offset in 0..nodes_at_depth {
            let idx = NodeIndex::new(depth, first_value + offset).unwrap();
            let node = InnerNode { left: node_hash, right: node_hash };
            subtree.insert_inner_node(idx, node);
        }
    }
    subtree
}

// Creates a sparse subtree with a single path from root to leaf (leftmost path).
fn create_sparse_subtree() -> Subtree {
    let root_index = NodeIndex::new(ROOT_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(root_index);

    let mut child_hash: Word = [Felt::ONE; 4].into();
    let mut current_idx = NodeIndex::new(ROOT_DEPTH + SUBTREE_DEPTH, 0).unwrap();

    for _ in 0..SUBTREE_DEPTH {
        let depth = current_idx.depth();
        let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, depth + 1);
        let node = InnerNode { left: child_hash, right: empty_hash };
        child_hash = node.hash();
        subtree.insert_inner_node(current_idx, node);
        current_idx = current_idx.parent();
    }
    subtree
}

benchmark_with_setup_data! {
    subtree_serialize_dense,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "serialize_dense",
    create_dense_subtree,
    |b: &mut criterion::Bencher, subtree: &Subtree| {
        b.iter(|| hint::black_box(subtree.to_vec()))
    },
}

benchmark_with_setup_data! {
    subtree_deserialize_dense,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "deserialize_dense",
    || {
        let subtree = create_dense_subtree();
        (subtree.root_index(), subtree.to_vec())
    },
    |b: &mut criterion::Bencher, (root_index, bytes): &(NodeIndex, Vec<u8>)| {
        b.iter(|| hint::black_box(Subtree::from_vec(*root_index, bytes).unwrap()))
    },
}

benchmark_with_setup_data! {
    subtree_serialize_sparse,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "serialize_sparse",
    create_sparse_subtree,
    |b: &mut criterion::Bencher, subtree: &Subtree| {
        b.iter(|| hint::black_box(subtree.to_vec()))
    },
}

benchmark_with_setup_data! {
    subtree_deserialize_sparse,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "deserialize_sparse",
    || {
        let subtree = create_sparse_subtree();
        (subtree.root_index(), subtree.to_vec())
    },
    |b: &mut criterion::Bencher, (root_index, bytes): &(NodeIndex, Vec<u8>)| {
        b.iter(|| hint::black_box(Subtree::from_vec(*root_index, bytes).unwrap()))
    },
}

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

// === Memory Storage Benchmarks ===

benchmark_with_setup_data! {
    memory_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries_sequential(256);
        let keys = generate_test_keys_sequential(10);
        let storage = MemoryStorage::new();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        (smt, keys)
    },
    |b: &mut criterion::Bencher, (smt, keys): &(LargeSmt<MemoryStorage>, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.open(key));
            }
        })
    },
}

benchmark_with_setup_data! {
    memory_smt_compute_mutations,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compute_mutations",
    || {
        let entries = generate_smt_entries_sequential(256);
        let storage = MemoryStorage::new();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        let new_entries = generate_smt_entries_sequential(10_000);
        (smt, new_entries)
    },
    |b: &mut criterion::Bencher, (smt, new_entries): &(LargeSmt<MemoryStorage>, Vec<(Word, Word)>)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

benchmark_batch! {
    memory_smt_apply_mutations,
    &[100, 1_000, 10_000],
    |b: &mut criterion::Bencher, entry_count: usize| {
        use criterion::BatchSize;

        let base_entries = generate_smt_entries_sequential(256);

        b.iter_batched(
            || {
                let storage = MemoryStorage::new();
                let smt = LargeSmt::with_entries(storage, base_entries.clone()).unwrap();
                let new_entries = generate_smt_entries_sequential(entry_count);
                let mutations = smt.compute_mutations(new_entries).unwrap();
                (smt, mutations)
            },
            |(mut smt, mutations)| {
                smt.apply_mutations(mutations).unwrap();
            },
            BatchSize::LargeInput,
        )
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

benchmark_batch! {
    memory_smt_insert_batch,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let base_entries = generate_smt_entries_sequential(256);
        let storage = MemoryStorage::new();
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

criterion_group!(
    memory_smt_benchmark_group,
    memory_smt_open,
    memory_smt_compute_mutations,
    memory_smt_apply_mutations,
    memory_smt_insert_batch,
);

criterion_group!(
    subtree_benchmark_group,
    subtree_serialize_dense,
    subtree_deserialize_dense,
    subtree_serialize_sparse,
    subtree_deserialize_sparse,
);

criterion_main!(large_smt_benchmark_group, memory_smt_benchmark_group, subtree_benchmark_group);
