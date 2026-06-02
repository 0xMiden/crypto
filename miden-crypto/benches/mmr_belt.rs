//! MMR vs experimental Merkle Mountain Belt benchmarks.
//!
//! The belt implementation benchmarked here is a reference prototype behind the `internal`
//! feature. It keeps in-memory hash-array state to derive summaries/proofs, so these numbers
//! should be read as construction-comparison data rather than production storage performance.

use std::{hint, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::mmr::{
        Mmr, MmrPeaks,
        belt::{BeltSummary, MmrBelt},
    },
};

mod common;
use common::data::{WordPattern, generate_word_pattern, generate_words_pattern};

const MMR_BELT_SIZES: &[usize] = &[1_000, 1_023, 1_024, 50_000, 65_535, 65_536];
const RECENCIES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1_024, 4_096, 16_384];
const APPEND_SEQUENCE_LEN: usize = 1_024;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const SAMPLE_SIZE: usize = 20;

#[derive(Clone)]
struct MmrBeltBenchData {
    leaves: Vec<Word>,
    mmr: Mmr,
    peaks: MmrPeaks,
    belt: MmrBelt,
    belt_summary: BeltSummary,
}

impl MmrBeltBenchData {
    fn build(size: usize) -> Self {
        let leaves = generate_words_pattern(size, WordPattern::Sequential);
        let mmr = Mmr::try_from_iter(leaves.iter().copied()).unwrap();
        let peaks = mmr.peaks();

        let mut belt = MmrBelt::new();
        for leaf in leaves.iter().copied() {
            belt.add(leaf).unwrap();
        }
        let belt_summary = belt.summary();

        Self { leaves, mmr, peaks, belt, belt_summary }
    }
}

fn append_sequence(start: usize) -> Vec<Word> {
    (start..start + APPEND_SEQUENCE_LEN)
        .map(|idx| generate_word_pattern(idx as u64, WordPattern::Sequential))
        .collect()
}

fn bench_mmr_belt_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-build");
    configure_group(&mut group);

    for &size in MMR_BELT_SIZES {
        group.bench_with_input(BenchmarkId::new("current-mmr", size), &size, |b, &size| {
            b.iter_batched(
                || generate_words_pattern(size, WordPattern::Sequential),
                |leaves| {
                    hint::black_box(Mmr::try_from_iter(leaves).unwrap());
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("belt-prototype", size), &size, |b, &size| {
            b.iter_batched(
                || generate_words_pattern(size, WordPattern::Sequential),
                |leaves| {
                    let mut belt = MmrBelt::new();
                    for leaf in leaves {
                        belt.add(leaf).unwrap();
                    }
                    hint::black_box(belt);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_mmr_belt_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-append");
    configure_group(&mut group);

    for &size in MMR_BELT_SIZES {
        let data = MmrBeltBenchData::build(size);
        let next_leaf = generate_word_pattern(size as u64, WordPattern::Sequential);

        group.bench_with_input(BenchmarkId::new("current-mmr", size), &size, |b, _| {
            b.iter_batched(
                || data.mmr.clone(),
                |mut mmr| {
                    mmr.add(hint::black_box(next_leaf)).unwrap();
                    hint::black_box(mmr);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("belt-prototype", size), &size, |b, _| {
            b.iter_batched(
                || data.belt.clone(),
                |mut belt| {
                    belt.add(hint::black_box(next_leaf)).unwrap();
                    hint::black_box(belt);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("current-mmr-and-commitment", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || data.mmr.clone(),
                    |mut mmr| {
                        mmr.add(hint::black_box(next_leaf)).unwrap();
                        hint::black_box(mmr.peaks().hash_peaks());
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("belt-prototype-and-summary", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || data.belt.clone(),
                    |mut belt| {
                        belt.add(hint::black_box(next_leaf)).unwrap();
                        hint::black_box(belt.summary());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_mmr_belt_append_sequence(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-append-sequence");
    configure_group(&mut group);
    group.throughput(criterion::Throughput::Elements(APPEND_SEQUENCE_LEN as u64));

    for &size in MMR_BELT_SIZES {
        let data = MmrBeltBenchData::build(size);
        let leaves = append_sequence(size);

        group.bench_with_input(BenchmarkId::new("current-mmr", size), &size, |b, _| {
            b.iter_batched_ref(
                || (data.mmr.clone(), leaves.clone()),
                |(mmr, leaves)| {
                    for leaf in leaves.iter().copied() {
                        mmr.add(hint::black_box(leaf)).unwrap();
                    }
                    hint::black_box(mmr);
                },
                BatchSize::LargeInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("belt-prototype", size), &size, |b, _| {
            b.iter_batched_ref(
                || (data.belt.clone(), leaves.clone()),
                |(belt, leaves)| {
                    for leaf in leaves.iter().copied() {
                        belt.add(hint::black_box(leaf)).unwrap();
                    }
                    hint::black_box(belt);
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn bench_mmr_belt_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-commitment");
    configure_group(&mut group);

    for &size in MMR_BELT_SIZES {
        let data = MmrBeltBenchData::build(size);

        group.bench_with_input(BenchmarkId::new("current-mmr-hash-peaks", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.peaks.hash_peaks());
            });
        });

        group.bench_with_input(BenchmarkId::new("belt-summary", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.belt.summary());
            });
        });
    }

    group.finish();
}

fn bench_mmr_belt_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-open");
    configure_group(&mut group);

    for &size in MMR_BELT_SIZES {
        let data = MmrBeltBenchData::build(size);

        group.bench_with_input(BenchmarkId::new("current-mmr-oldest", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.mmr.open(0).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("belt-oldest", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.belt.open(0).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("current-mmr-newest", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.mmr.open(size - 1).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("belt-newest", size), &size, |b, _| {
            b.iter(|| {
                hint::black_box(data.belt.open(size - 1).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_mmr_belt_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-verify");
    configure_group(&mut group);

    for &size in MMR_BELT_SIZES {
        let data = MmrBeltBenchData::build(size);
        let oldest_mmr_proof = data.mmr.open(0).unwrap();
        let newest_mmr_proof = data.mmr.open(size - 1).unwrap();
        let oldest_belt_proof = data.belt.open(0).unwrap();
        let newest_belt_proof = data.belt.open(size - 1).unwrap();

        group.bench_with_input(BenchmarkId::new("current-mmr-oldest", size), &size, |b, _| {
            b.iter(|| {
                data.peaks
                    .verify(
                        hint::black_box(data.leaves[0]),
                        hint::black_box(oldest_mmr_proof.clone()),
                    )
                    .unwrap();
            });
        });

        group.bench_with_input(
            BenchmarkId::new("current-mmr-committed-oldest", size),
            &size,
            |b, _| {
                let commitment = data.peaks.hash_peaks();
                b.iter(|| {
                    assert_eq!(hint::black_box(data.peaks.hash_peaks()), commitment);
                    data.peaks
                        .verify(
                            hint::black_box(data.leaves[0]),
                            hint::black_box(oldest_mmr_proof.clone()),
                        )
                        .unwrap();
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("belt-oldest", size), &size, |b, _| {
            b.iter(|| {
                assert!(
                    hint::black_box(&oldest_belt_proof).verify(hint::black_box(&data.belt_summary))
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("current-mmr-newest", size), &size, |b, _| {
            b.iter(|| {
                data.peaks
                    .verify(
                        hint::black_box(data.leaves[size - 1]),
                        hint::black_box(newest_mmr_proof.clone()),
                    )
                    .unwrap();
            });
        });

        group.bench_with_input(
            BenchmarkId::new("current-mmr-committed-newest", size),
            &size,
            |b, _| {
                let commitment = data.peaks.hash_peaks();
                b.iter(|| {
                    assert_eq!(hint::black_box(data.peaks.hash_peaks()), commitment);
                    data.peaks
                        .verify(
                            hint::black_box(data.leaves[size - 1]),
                            hint::black_box(newest_mmr_proof.clone()),
                        )
                        .unwrap();
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("belt-newest", size), &size, |b, _| {
            b.iter(|| {
                assert!(
                    hint::black_box(&newest_belt_proof).verify(hint::black_box(&data.belt_summary))
                );
            });
        });
    }

    group.finish();
}

fn bench_mmr_belt_recency(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr-belt-recency");
    configure_group(&mut group);

    for &size in &[50_000, 65_536] {
        let data = MmrBeltBenchData::build(size);

        for &recency in RECENCIES {
            if recency > size {
                continue;
            }
            let position = size - recency;
            let mmr_proof = data.mmr.open(position).unwrap();
            let belt_proof = data.belt.open(position).unwrap();

            group.bench_with_input(
                BenchmarkId::new("current-mmr-verify", format!("{size}/{recency}")),
                &(size, recency),
                |b, _| {
                    b.iter(|| {
                        data.peaks
                            .verify(
                                hint::black_box(data.leaves[position]),
                                hint::black_box(mmr_proof.clone()),
                            )
                            .unwrap();
                    });
                },
            );

            let commitment = data.peaks.hash_peaks();
            group.bench_with_input(
                BenchmarkId::new("current-mmr-committed-verify", format!("{size}/{recency}")),
                &(size, recency),
                |b, _| {
                    b.iter(|| {
                        assert_eq!(hint::black_box(data.peaks.hash_peaks()), commitment);
                        data.peaks
                            .verify(
                                hint::black_box(data.leaves[position]),
                                hint::black_box(mmr_proof.clone()),
                            )
                            .unwrap();
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("belt-verify", format!("{size}/{recency}")),
                &(size, recency),
                |b, _| {
                    b.iter(|| {
                        assert!(
                            hint::black_box(&belt_proof)
                                .verify(hint::black_box(&data.belt_summary))
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

fn configure_group<M: criterion::measurement::Measurement>(
    group: &mut criterion::BenchmarkGroup<'_, M>,
) {
    group.measurement_time(MEASUREMENT_TIME);
    group.sample_size(SAMPLE_SIZE);
}

criterion_group!(
    mmr_belt_benches,
    bench_mmr_belt_build,
    bench_mmr_belt_append,
    bench_mmr_belt_append_sequence,
    bench_mmr_belt_commitment,
    bench_mmr_belt_open,
    bench_mmr_belt_verify,
    bench_mmr_belt_recency,
);
criterion_main!(mmr_belt_benches);
