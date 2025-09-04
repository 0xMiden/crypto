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

benchmark_aead!(aead_rpo, "AEAD RPO", bench_aead_rpo_bytes, bench_aead_rpo_felts, aead_rpo_group);
criterion_main!(aead_rpo_group);
