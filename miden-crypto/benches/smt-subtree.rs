use std::{fmt::Debug, hint, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, ONE, Word,
    merkle::{NodeIndex, SMT_DEPTH, SmtLeaf, SubtreeLeaf, build_subtree_for_bench},
};
use rand_utils::prng_array;
use winter_utils::Randomizable;

const PAIR_COUNTS: [u64; 5] = [1, 64, 128, 192, 256];

fn smt_subtree_even(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("subtree8-even");

    for pair_count in PAIR_COUNTS {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    let entries: Vec<(Word, Word)> = (0..pair_count)
                        .map(|n| {
                            // A single depth-8 subtree can have a maximum of 255 leaves.
                            let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                            let key = Word::new([
                                generate_value(&mut seed),
                                ONE,
                                Felt::new(n),
                                Felt::new(leaf_index),
                            ]);
                            let value = generate_word(&mut seed);
                            (key, value)
                        })
                        .collect();

                    let mut leaves: Vec<_> = entries
                        .iter()
                        .map(|(key, value)| {
                            let leaf = SmtLeaf::new_single(*key, *value);
                            let col = NodeIndex::from(leaf.index()).value();
                            let hash = leaf.hash();
                            SubtreeLeaf { col, hash }
                        })
                        .collect();
                    leaves.sort();
                    leaves.dedup_by_key(|leaf| leaf.col);
                    leaves
                },
                |leaves| {
                    // Benchmarked function.
                    let (subtree, _) = build_subtree_for_bench(
                        hint::black_box(leaves),
                        hint::black_box(SMT_DEPTH),
                        hint::black_box(SMT_DEPTH),
                    );
                    assert!(!subtree.is_empty());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn smt_subtree_random(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("subtree8-rand");

    for pair_count in PAIR_COUNTS {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    let entries: Vec<(Word, Word)> = (0..pair_count)
                        .map(|i| {
                            let leaf_index: u8 = generate_value(&mut seed);
                            let key =
                                Word::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index as u64)]);
                            let value = generate_word(&mut seed);
                            (key, value)
                        })
                        .collect();

                    let mut leaves: Vec<_> = entries
                        .iter()
                        .map(|(key, value)| {
                            let leaf = SmtLeaf::new_single(*key, *value);
                            let col = NodeIndex::from(leaf.index()).value();
                            let hash = leaf.hash();
                            SubtreeLeaf { col, hash }
                        })
                        .collect();
                    leaves.sort();
                    leaves.dedup_by_key(|leaf| leaf.col);
                    leaves
                },
                |leaves| {
                    let (subtree, _) = build_subtree_for_bench(
                        hint::black_box(leaves),
                        hint::black_box(SMT_DEPTH),
                        hint::black_box(SMT_DEPTH),
                    );
                    assert!(!subtree.is_empty());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(40))
        .sample_size(60)
        .configure_from_args();
    targets = smt_subtree_even, smt_subtree_random
}
criterion_main!(smt_subtree_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_value<T: Copy + Debug + Randomizable>(seed: &mut [u8; 32]) -> T {
    *seed = prng_array(*seed);
    let value: [T; 1] = rand_utils::prng_array(*seed);
    value[0]
}

fn generate_word(seed: &mut [u8; 32]) -> Word {
    *seed = prng_array(*seed);
    let nums: [u64; 4] = prng_array(*seed);
    Word::new([Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])])
}
