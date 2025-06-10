use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word,
    merkle::{LeafIndex, SimpleSmt},
};
use rand_utils::prng_array;
use seq_macro::seq;

fn smt_rpo(c: &mut Criterion) {
    // setup trees

    let mut seed = [0u8; 32];
    let leaf = generate_word(&mut seed);

    seq!(DEPTH in 14..=20 {
        let leaves = ((1 << DEPTH) - 1) as u64;
        for count in [1, leaves / 2, leaves] {
            let entries: Vec<_> = (0..count)
                .map(|i| {
                    let word = generate_word(&mut seed);
                    (i, word)
                })
                .collect();
            let mut tree = SimpleSmt::<DEPTH>::with_leaves(entries).unwrap();

            // benchmark 1
            let mut insert = c.benchmark_group("smt update_leaf".to_string());
            {
                let depth = DEPTH;
                let key = count >> 2;
                insert.bench_with_input(
                    format!("simple smt(depth:{depth},count:{count})"),
                    &(key, leaf),
                    |b, (key, leaf)| {
                        b.iter(|| {
                            tree.insert(black_box(LeafIndex::<DEPTH>::new(*key).unwrap()), black_box(*leaf));
                        });
                    },
                );

            }
            insert.finish();

            // benchmark 2
            let mut path = c.benchmark_group("smt get_leaf_path".to_string());
            {
                let depth = DEPTH;
                let key = count >> 2;
                path.bench_with_input(
                    format!("simple smt(depth:{depth},count:{count})"),
                    &key,
                    |b, key| {
                        b.iter(|| {
                            tree.open(black_box(&LeafIndex::<DEPTH>::new(*key).unwrap()));
                        });
                    },
                );

            }
            path.finish();
        }
    });
}

criterion_group!(smt_group, smt_rpo);
criterion_main!(smt_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_word(seed: &mut [u8; 32]) -> Word {
    *seed = prng_array(*seed);
    let nums: [u64; 4] = prng_array(*seed);
    Word::new([Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])])
}
