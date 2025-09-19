//! Benchmark for building a [`miden_crypto::merkle::MerkleTree`]. This is intended to be compared
//! with the results from `benches/smt-subtree.rs`, as building a fully balanced Merkle tree with
//! 256 leaves should indicate the *absolute best* performance we could *possibly* get for building
//! a depth-8 sparse Merkle subtree, though practically speaking building a fully balanced Merkle
//! tree will perform better than the sparse version. At the time of this writing (2024/11/24), this
//! benchmark is about four times more efficient than the equivalent benchmark in
//! `benches/smt-subtree.rs`.
use std::{hint, time::Duration};

use criterion::{BatchSize, Bencher, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{MerklePath, MerkleTree, NodeIndex},
};

mod common;
use common::data::*;

benchmark_multi!(
    balanced_merkle_even,
    "balanced-merkle-even",
    &[4, 8, 16, 32, 64, 128, 256],
    |b: &mut Bencher<'_>, num_leaves: &usize| {
        b.iter_batched(
            || {
                let entries = generate_words_merkle_std(*num_leaves);
                assert_eq!(entries.len(), *num_leaves);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), num_leaves.ilog2() as u8);
            },
            BatchSize::SmallInput,
        );
    }
);

benchmark_multi!(
    balanced_merkle_rand,
    "balanced-merkle-rand",
    &[4, 8, 16, 32, 64, 128, 256],
    |b: &mut Bencher<'_>, num_leaves: &usize| {
        let mut seed = [0u8; 32];
        b.iter_batched(
            || {
                let entries: Vec<Word> =
                    (0..*num_leaves).map(|_| generate_word(&mut seed)).collect();
                assert_eq!(entries.len(), *num_leaves);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), num_leaves.ilog2() as u8);
            },
            BatchSize::SmallInput,
        );
    }
);

// MERKLE TREE BENCHMARKS
// ================================================================================================

benchmark_with_setup_data!(
    merkle_tree_root,
    Duration::from_secs(10),
    10,
    "merkle-tree-root",
    || {
        let entries = generate_words_merkle_std(256);
        MerkleTree::new(&entries).unwrap()
    },
    |b: &mut criterion::Bencher<'_>, tree: &MerkleTree| {
        b.iter(|| {
            hint::black_box(tree.root());
        });
    }
);

fn merkle_tree_depth(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(hint::black_box(&entries)).unwrap();

    c.bench_function("merkle-tree-depth", |b| {
        b.iter(|| {
            hint::black_box(tree.depth());
        });
    });
}

fn merkle_tree_get_node(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(hint::black_box(&entries)).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();

    c.bench_function("merkle-tree-get-node", |b| {
        b.iter(|| {
            tree.get_node(hint::black_box(index)).unwrap();
        });
    });
}

fn merkle_tree_get_path(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(hint::black_box(&entries)).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();

    c.bench_function("merkle-tree-get-path", |b| {
        b.iter(|| {
            tree.get_path(hint::black_box(index)).unwrap();
        });
    });
}

fn merkle_tree_leaves(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();

    c.bench_function("merkle-tree-leaves", |b| {
        b.iter(|| {
            hint::black_box(tree.leaves().collect::<Vec<_>>());
        });
    });
}

fn merkle_tree_inner_nodes(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();

    c.bench_function("merkle-tree-inner-nodes", |b| {
        b.iter(|| {
            hint::black_box(tree.inner_nodes().collect::<Vec<_>>());
        });
    });
}

benchmark_batch!(
    merkle_tree_update_leaf,
    &[1, 16, 32, 64, 128],
    |b: &mut Bencher<'_>, leaf_count: usize| {
        let entries = generate_words_merkle_std(256);
        let mut tree = MerkleTree::new(&entries).unwrap();
        let mut seed = [0u8; 32];
        b.iter(|| {
            for i in 0..leaf_count {
                tree.update_leaf(i as u64, hint::black_box(generate_word(&mut seed))).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
);

// MERKLE PATH BENCHMARKS
// ================================================================================================

fn merkle_path_new(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();
    let path_nodes = tree.get_path(index).unwrap();

    c.bench_function("merkle-path-new", |b| {
        b.iter(|| {
            let _path = MerklePath::new(hint::black_box(path_nodes.nodes().to_vec()));
        });
    });
}

fn merkle_path_compute_root(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();
    let path = tree.get_path(index).unwrap();
    let leaf = entries[0];

    c.bench_function("merkle-path-compute-root", |b| {
        b.iter(|| {
            let _root = path.compute_root(0, hint::black_box(leaf)).unwrap();
        });
    });
}

fn merkle_path_verify(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();
    let path = tree.get_path(index).unwrap();
    let leaf = entries[0];
    let root = tree.root();

    c.bench_function("merkle-path-verify", |b| {
        b.iter(|| {
            path.verify(0, hint::black_box(leaf), hint::black_box(&root)).unwrap();
        });
    });
}

fn merkle_path_authenticated_nodes(c: &mut Criterion) {
    let entries = generate_words_merkle_std(256);
    let tree = MerkleTree::new(&entries).unwrap();
    let index = NodeIndex::new(8, 0).unwrap();
    let path = tree.get_path(index).unwrap();
    let leaf = entries[0];

    c.bench_function("merkle-path-authenticated-nodes", |b| {
        b.iter(|| {
            let nodes = path.authenticated_nodes(0, hint::black_box(leaf)).unwrap();
            let nodes: Vec<_> = nodes.collect();
            hint::black_box(nodes);
        });
    });
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .configure_from_args();
    targets =
        balanced_merkle_even,
        balanced_merkle_rand,
        // MerkleTree benchmarks
        merkle_tree_root,
        merkle_tree_depth,
        merkle_tree_get_node,
        merkle_tree_get_path,
        merkle_tree_leaves,
        merkle_tree_inner_nodes,
        merkle_tree_update_leaf,
        // MerklePath benchmarks
        merkle_path_new,
        merkle_path_compute_root,
        merkle_path_verify,
        merkle_path_authenticated_nodes
}

criterion_main!(smt_subtree_group);
