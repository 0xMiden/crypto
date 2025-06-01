//! Benchmark for building a [`miden_crypto::merkle::MerkleTree`]. This is intended to be compared
//! with the results from `benches/smt-subtree.rs`, as building a fully balanced Merkle tree with
//! 256 leaves should indicate the *absolute best* performance we could *possibly* get for building
//! a depth-8 sparse Merkle subtree, though practically speaking building a fully balanced Merkle
//! tree will perform better than the sparse version. At the time of this writing (2024/11/24), this
//! benchmark is about four times more efficient than the equivalent benchmark in
//! `benches/smt-subtree.rs`.
use std::{hint, time::Duration};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use miden_crypto::{Felt, ONE, Word, merkle::MerkleTree};
use rand_utils::prng_array;

fn balanced_merkle_even(c: &mut Criterion) {
    c.bench_function("balanced-merkle-even", |b| {
        b.iter_batched(
            || {
                let entries: Vec<Word> =
                    (0..256).map(|i| Word::new([Felt::new(i), ONE, ONE, Felt::new(i)])).collect();
                assert_eq!(entries.len(), 256);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), 8);
            },
            BatchSize::SmallInput,
        );
    });
}

fn balanced_merkle_rand(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function("balanced-merkle-rand", |b| {
        b.iter_batched(
            || {
                let entries: Vec<Word> = (0..256).map(|_| generate_word(&mut seed)).collect();
                assert_eq!(entries.len(), 256);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), 8);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .configure_from_args();
    targets = balanced_merkle_even, balanced_merkle_rand
}
criterion_main!(smt_subtree_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_word(seed: &mut [u8; 32]) -> Word {
    *seed = prng_array(*seed);
    let nums: [u64; 4] = prng_array(*seed);
    Word::new([Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])])
}
