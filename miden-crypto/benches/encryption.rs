use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

mod common;
use common::{
    config::DATA_SIZES,
    data::{generate_byte_array_random, generate_byte_array_sequential},
};

benchmark_aead!(xchacha, "AEAD XChaCha20-Poly1305", bench_aead_xchacha_bytes, aead_xchacha_group);

criterion_group!(xchacha_encryption_group, bench_aead_xchacha_bytes);
criterion_main!(xchacha_encryption_group);
