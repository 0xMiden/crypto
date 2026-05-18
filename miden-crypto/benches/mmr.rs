//! Merkle Mountain Range frontier benchmarks.
//!
//! These benchmarks compare the legacy peak-hash commitment API with the rooted frontier API.

use std::hint;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::mmr::{MerkleFrontier, Mmr, MmrPeaks},
};

mod common;
use common::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{WordPattern, generate_word_pattern, generate_words_pattern},
};

// Includes mixed sizes plus 2^k - 1 / 2^k pairs to expose hamming-weight effects.
const MMR_SIZES: &[usize] = &[1_000, 1_023, 1_024, 50_000, 65_535, 65_536];

struct MmrBenchData {
    mmr: Mmr,
    peaks: MmrPeaks,
    frontier: MerkleFrontier,
    leaf_pos: usize,
    leaf: Word,
}

fn build_mmr(size: usize) -> Mmr {
    Mmr::try_from_iter(generate_words_pattern(size, WordPattern::Sequential)).unwrap()
}

fn build_data(size: usize) -> MmrBenchData {
    let mmr = build_mmr(size);
    let peaks = mmr.peaks();
    let frontier = mmr.frontier();
    let leaf_pos = 0;
    let leaf = generate_word_pattern(leaf_pos as u64, WordPattern::Sequential);

    MmrBenchData { mmr, peaks, frontier, leaf_pos, leaf }
}

// === MMR Commitment Benchmarks ===

fn bench_mmr_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-commitment");
    group.measurement_time(DEFAULT_MEASUREMENT_TIME);
    group.sample_size(DEFAULT_SAMPLE_SIZE);

    for &size in MMR_SIZES {
        group.bench_with_input(BenchmarkId::new("legacy-hash-peaks", size), &size, |b, &size| {
            let data = build_data(size);
            b.iter(|| {
                hint::black_box(data.peaks.hash_peaks());
            });
        });

        group.bench_with_input(BenchmarkId::new("frontier-root", size), &size, |b, &size| {
            let data = build_data(size);
            b.iter(|| {
                hint::black_box(data.frontier.root());
            });
        });
    }

    group.finish();
}

// === MMR Append Benchmarks ===

fn bench_mmr_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-append");
    group.measurement_time(DEFAULT_MEASUREMENT_TIME);
    group.sample_size(DEFAULT_SAMPLE_SIZE);

    for &size in MMR_SIZES {
        group.bench_with_input(BenchmarkId::new("frontier-append", size), &size, |b, &size| {
            let data = build_data(size);
            let next_leaf = generate_word_pattern(size as u64, WordPattern::Sequential);

            b.iter_batched(
                || data.frontier.clone(),
                |mut frontier| {
                    frontier.append(hint::black_box(next_leaf)).unwrap();
                    hint::black_box(frontier);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("frontier-append-and-root", size),
            &size,
            |b, &size| {
                let data = build_data(size);
                let next_leaf = generate_word_pattern(size as u64, WordPattern::Sequential);

                b.iter_batched(
                    || data.frontier.clone(),
                    |mut frontier| {
                        frontier.append(hint::black_box(next_leaf)).unwrap();
                        hint::black_box(frontier.root());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// === MMR Proof Opening Benchmarks ===

fn bench_mmr_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-open");
    group.measurement_time(DEFAULT_MEASUREMENT_TIME);
    group.sample_size(DEFAULT_SAMPLE_SIZE);

    for &size in MMR_SIZES {
        group.bench_with_input(BenchmarkId::new("legacy-proof", size), &size, |b, &size| {
            let data = build_data(size);

            b.iter(|| {
                hint::black_box(data.mmr.open(data.leaf_pos).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("frontier-proof", size), &size, |b, &size| {
            let data = build_data(size);

            b.iter(|| {
                hint::black_box(data.mmr.open_frontier(data.leaf_pos).unwrap());
            });
        });
    }

    group.finish();
}

// === MMR Proof Verification Benchmarks ===

fn bench_mmr_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-verify");
    group.measurement_time(DEFAULT_MEASUREMENT_TIME);
    group.sample_size(DEFAULT_SAMPLE_SIZE);

    for &size in MMR_SIZES {
        group.bench_with_input(BenchmarkId::new("legacy-peak-local", size), &size, |b, &size| {
            let data = build_data(size);
            let proof = data.mmr.open(data.leaf_pos).unwrap();

            b.iter(|| {
                data.peaks
                    .verify(hint::black_box(data.leaf), hint::black_box(proof.clone()))
                    .unwrap();
            });
        });

        group.bench_with_input(
            BenchmarkId::new("legacy-committed-peaks", size),
            &size,
            |b, &size| {
                let data = build_data(size);
                let commitment = data.peaks.hash_peaks();
                let proof = data.mmr.open(data.leaf_pos).unwrap();

                b.iter(|| {
                    assert_eq!(data.peaks.hash_peaks(), hint::black_box(commitment));
                    data.peaks
                        .verify(hint::black_box(data.leaf), hint::black_box(proof.clone()))
                        .unwrap();
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("frontier-root", size), &size, |b, &size| {
            let data = build_data(size);
            let root = data.frontier.root();
            let proof = data.mmr.open_frontier(data.leaf_pos).unwrap();

            b.iter(|| {
                proof
                    .path
                    .verify(
                        data.leaf_pos as u64,
                        hint::black_box(proof.value),
                        hint::black_box(&root),
                    )
                    .unwrap();
            });
        });
    }

    group.finish();
}

// === Benchmark Group Definition ===

criterion_group!(
    mmr_benches,
    bench_mmr_commitments,
    bench_mmr_append,
    bench_mmr_open,
    bench_mmr_verify,
);
criterion_main!(mmr_benches);
