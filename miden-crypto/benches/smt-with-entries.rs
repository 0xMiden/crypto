use std::{fmt::Debug, hint, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{Felt, ONE, Word, merkle::Smt};
use rand_utils::prng_array;
use winter_utils::Randomizable;

// 2^0, 2^4, 2^8, 2^12, 2^16
const PAIR_COUNTS: [u64; 6] = [1, 16, 256, 4096, 65536, 1_048_576];

fn smt_with_entries(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("smt-with-entries");

    for pair_count in PAIR_COUNTS {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    prepare_entries(pair_count, &mut seed)
                },
                |entries| {
                    // Benchmarked function.
                    Smt::with_entries(hint::black_box(entries)).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = smt_with_entries_group;
    config = Criterion::default()
        //.measurement_time(Duration::from_secs(960))
        .measurement_time(Duration::from_secs(60))
        .sample_size(10)
        .configure_from_args();
    targets = smt_with_entries
}
criterion_main!(smt_with_entries_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn prepare_entries(pair_count: u64, seed: &mut [u8; 32]) -> Vec<(Word, Word)> {
    let entries: Vec<(Word, Word)> = (0..pair_count)
        .map(|i| {
            let count = pair_count as f64;
            let idx = ((i as f64 / count) * (count)) as u64;
            let key = Word::new([generate_value(seed), ONE, Felt::new(i), Felt::new(idx)]);
            let value = generate_word(seed);
            (key, value)
        })
        .collect();
    entries
}

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
