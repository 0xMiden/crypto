use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

mod common;
use common::{
    config::DATA_SIZES,
    data::{generate_byte_array_random, generate_byte_array_sequential},
};

benchmark_aead!(xchacha, "AEAD XChaCha20-Poly1305");

criterion_group!(xchacha_encryption_group, benchmark_xchacha_bytes);
criterion_main!(xchacha_encryption_group);
