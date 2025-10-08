use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
// Import the historical module - note it's conditionally compiled with std feature
#[cfg(feature = "std")]
use miden_crypto::merkle::historical::SmtWithHistory;
use miden_crypto::{EMPTY_WORD, Word, hash::rpo::Rpo256, merkle::Smt};

/// Generate a deterministic word from a seed
fn generate_word(seed: &mut [u8; 32]) -> Word {
    // Increment seed
    for i in 0..32 {
        seed[i] = seed[i].wrapping_add(1);
        if seed[i] != 0 {
            break;
        }
    }

    let digest = Rpo256::hash(seed);
    digest.into()
}

/// Setup a SmtWithHistory with specified number of keys and reversions
#[cfg(feature = "std")]
fn setup_smt_with_history(num_keys: usize, num_reversions: usize) -> (SmtWithHistory, Vec<Word>) {
    let mut seed = [0u8; 32];
    let smt_with_history = SmtWithHistory::new(Smt::default(), 0u64);
    let mut keys_used = Vec::new();

    // Apply mutations to create history
    for _rev in 0..=num_reversions {
        let mut mutations = Vec::new();
        for _key_idx in 0..num_keys {
            let key = generate_word(&mut seed);
            let value = generate_word(&mut seed);
            mutations.push((key, value));

            if keys_used.len() < num_keys {
                keys_used.push(key);
            }
        }

        // Create and apply mutation set
        let mutation_set = smt_with_history.compute_mutations(mutations).unwrap();
        smt_with_history.apply_mutations(mutation_set.clone()).unwrap();
    }

    (smt_with_history, keys_used)
}

/// Create vanilla Smt at different historical states
fn create_vanilla_states(num_keys: usize, num_reversions: usize) -> (Vec<Smt>, Vec<Word>) {
    let mut seed = [0u8; 32];
    let mut states = Vec::new();
    let mut current_smt = Smt::default();
    let mut keys_used = Vec::new();

    states.push(current_smt.clone());

    for _rev in 0..=num_reversions {
        for _key_idx in 0..num_keys {
            let key = generate_word(&mut seed);
            let value = generate_word(&mut seed);
            let _ = current_smt.insert(key, value);

            if keys_used.len() < num_keys {
                keys_used.push(key);
            }
        }
        states.push(current_smt.clone());
    }

    (states, keys_used)
}

/// Benchmark historical access at different depths
#[cfg(feature = "std")]
fn bench_historical_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_historical_access");

    // Test configurations
    let key_counts = vec![1, 10, 100, 1000];
    let reversion_depths = vec![0, 1, 5, 10, 20];

    for num_keys in key_counts {
        for &reversion_depth in &reversion_depths {
            // Skip impossible configurations
            if reversion_depth > SmtWithHistory::MAX_HISTORY {
                continue;
            }

            let bench_id =
                BenchmarkId::new(format!("historical/{}_keys", num_keys), reversion_depth);

            let (smt_hist, keys) = setup_smt_with_history(num_keys, reversion_depth);
            if reversion_depth >= smt_hist.history_len() {
                continue;
            }

            // Benchmark SmtWithHistory
            group.bench_function(bench_id, move |b| {
                let test_key = keys.get(0).copied().unwrap_or(EMPTY_WORD);

                b.iter(|| {
                    smt_hist
                        .historical_view(black_box(reversion_depth as u64))
                        .unwrap()
                        .open(black_box(&test_key));
                });
            });

            // Benchmark vanilla approach
            let bench_id_vanilla =
                BenchmarkId::new(format!("vanilla/{}_keys", num_keys), reversion_depth);

            group.bench_function(bench_id_vanilla, |b| {
                let (states, keys) = create_vanilla_states(num_keys, reversion_depth);
                let test_key = keys.get(0).copied().unwrap_or(EMPTY_WORD);

                b.iter(|| {
                    // Access the state at the requested reversion depth
                    let state_idx = states.len() - 1 - reversion_depth;
                    states[state_idx].open(black_box(&test_key))
                });
            });
        }
    }

    group.finish();
}

/// Benchmark insertion performance with history tracking
#[cfg(feature = "std")]
fn bench_insertion_with_history(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_insertion");

    let key_counts = vec![10, 100, 1000];

    for num_keys in key_counts {
        // Benchmark SmtWithHistory insertions
        group.bench_function(BenchmarkId::new("with_history", num_keys), |b| {
            b.iter_batched(
                || {
                    let smt = SmtWithHistory::new(Smt::default(), 0);
                    let mut seed = [0u8; 32];
                    let mutations = Vec::from_iter((0..num_keys).map(|_| {
                        let key = generate_word(&mut seed);
                        let value = generate_word(&mut seed);
                        (key, value)
                    }));
                    (smt, mutations)
                },
                |(smt, mutations)| {
                    let mutation_set = smt.compute_mutations(mutations).unwrap();
                    smt.apply_mutations(black_box(mutation_set.clone())).unwrap();
                },
                BatchSize::SmallInput,
            );
        });

        // Benchmark vanilla Smt insertions
        group.bench_function(BenchmarkId::new("vanilla", num_keys), |b| {
            b.iter_batched(
                || {
                    let smt = Smt::default();
                    let mut seed = [0u8; 32];
                    let mutations = Vec::from_iter((0..num_keys).map(|_| {
                        let key = generate_word(&mut seed);
                        let value = generate_word(&mut seed);
                        (key, value)
                    }));
                    (smt, mutations)
                },
                |(mut smt, mutations)| {
                    for (key, value) in mutations {
                        let _ = smt.insert(black_box(key), black_box(value));
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark proof generation at different historical depths
#[cfg(feature = "std")]
fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_proof_generation");

    let key_counts = vec![10, 100, 1000];
    let reversion_depths = vec![0, 5, 10, 20];

    for num_keys in key_counts {
        for &history_depth in &reversion_depths {
            if history_depth >= SmtWithHistory::MAX_HISTORY {
                continue;
            }

            let bench_id =
                BenchmarkId::new(format!("historical_proof/{}_keys", num_keys), history_depth);

            let (smt, keys) = setup_smt_with_history(num_keys, history_depth);
            if history_depth >= smt.history_len() {
                continue;
            }
            group.bench_function(bench_id, move |b| {
                let test_key = keys.get(0).copied().unwrap_or(EMPTY_WORD);

                b.iter(|| {
                    smt.historical_view(black_box(history_depth as u64)).unwrap().open(&test_key)
                });
            });
        }
    }

    group.finish();
}

#[cfg(not(feature = "std"))]
fn bench_historical_access(_c: &mut Criterion) {}

#[cfg(not(feature = "std"))]
fn bench_insertion_with_history(_c: &mut Criterion) {}

#[cfg(not(feature = "std"))]
fn bench_cleanup(_c: &mut Criterion) {}

#[cfg(not(feature = "std"))]
fn bench_proof_generation(_c: &mut Criterion) {}

criterion_group!(
    name = historical_proofs;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(1))
        .warm_up_time(std::time::Duration::from_secs(1))
        .sample_size(10)
        .configure_from_args();
    targets = bench_historical_access,
    bench_insertion_with_history,
    bench_proof_generation
);
criterion_main!(historical_proofs);
