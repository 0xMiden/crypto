use criterion::{Criterion, black_box, criterion_group, criterion_main};
use miden_crypto::{
    Felt, PrimeCharacteristicRing, Word,
    merkle::{LeafIndex, SimpleSmt},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use seq_macro::seq;

fn smt_rpo(c: &mut Criterion) {
    // setup trees

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let leaf = generate_word(&mut rng);

    seq!(DEPTH in 14..=20 {
        let leaves = ((1 << DEPTH) - 1) as u64;
        for count in [1, leaves / 2, leaves] {

            let entries: Vec<_> = (0..count)
                .map(|i| {
                    let word = generate_word(&mut rng);
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
                            let _ = tree.insert(black_box(LeafIndex::<DEPTH>::new(*key).unwrap()), black_box(*leaf));
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

fn generate_word<R: RngCore>(rng: &mut R) -> Word {
    [
        Felt::from_u64(rng.next_u64()),
        Felt::from_u64(rng.next_u64()),
        Felt::from_u64(rng.next_u64()),
        Felt::from_u64(rng.next_u64()),
    ]
}
