use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_crypto::Felt;

mod common;
use common::{
    config::{DATA_SIZES, FELT_SIZES},
    data::{
        generate_byte_array_random, generate_byte_array_sequential, generate_felt_array_random,
        generate_felt_array_sequential,
    },
};

benchmark_aead_bytes!(aead_rpo, "AEAD RPO", bench_aead_rpo_bytes, aead_rpo_bytes_group);
benchmark_aead_field!(aead_rpo, "AEAD RPO", bench_aead_rpo_felts, aead_rpo_felts_group);

benchmark_aead_bytes!(
    xchacha,
    "AEAD XChaCha20-Poly1305",
    bench_aead_xchacha_bytes,
    aead_xchacha_bytes_group
);
benchmark_aead_field!(
    xchacha,
    "AEAD XChaCha20-Poly1305",
    bench_aead_xchacha_felts,
    aead_xchacha_felts_group
);

// Running the benchmarks:

criterion_main!(
    aead_rpo_bytes_group,
    aead_rpo_felts_group,
    aead_xchacha_bytes_group,
    aead_xchacha_felts_group
);
