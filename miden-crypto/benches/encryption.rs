use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_crypto::{
    Felt, ONE,
    encryption::aead_rpo::{Nonce, SecretKey},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod common;
use common::{
    config::{DATA_SIZES, FELT_SIZES},
    data::{
        generate_byte_array_random, generate_byte_array_sequential, generate_felt_array_random,
        generate_felt_array_sequential,
    },
};

// ================================================================================================
// BENCHMARK MACROS
// ================================================================================================

/// Macro to generate encryption/decryption benchmarks for field elements
macro_rules! benchmark_aead_felts {
    ($group_name:expr, $sizes:expr) => {
        fn benchmark_aead_felts(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            let mut rng = ChaCha20Rng::seed_from_u64(42);

            // Setup common test data
            let key = SecretKey::with_rng(&mut rng);
            let nonce_word = [ONE; 4].into();
            let associated_data: Vec<Felt> = generate_felt_array_sequential(8);

            for &size in $sizes {
                // Generate test data for this size
                let data: Vec<Felt> = generate_felt_array_random(size);

                group.throughput(Throughput::Elements(size as u64));

                // Encryption benchmark
                group.bench_with_input(
                    BenchmarkId::new("encrypt_felts", size),
                    &data,
                    |b, data| {
                        b.iter(|| {
                            black_box(key.encrypt_with_nonce(
                                black_box(data),
                                black_box(&associated_data),
                                black_box(Nonce::from_word(nonce_word)),
                            ))
                        });
                    },
                );

                // Decryption benchmark
                let encrypted =
                    key.encrypt_with_nonce(&data, &associated_data, Nonce::from_word(nonce_word));

                group.bench_with_input(
                    BenchmarkId::new("decrypt_felts", size),
                    &encrypted,
                    |b, encrypted| {
                        b.iter(|| {
                            black_box(key.decrypt(black_box(encrypted), &associated_data).unwrap())
                        });
                    },
                );
            }

            group.finish();
        }
    };
}

/// Macro to generate encryption/decryption benchmarks for bytes
macro_rules! benchmark_aead_bytes {
    ($group_name:expr, $sizes:expr) => {
        fn benchmark_aead_bytes(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            let mut rng = ChaCha20Rng::seed_from_u64(42);

            // Setup common test data
            let key = SecretKey::with_rng(&mut rng);
            let nonce_word = [ONE; 4].into();
            let associated_data = generate_byte_array_sequential(8);

            for &size in $sizes {
                // Generate test data for this size
                let data = generate_byte_array_random(size);

                group.throughput(Throughput::Bytes(size as u64));

                // Encryption benchmark
                group.bench_with_input(
                    BenchmarkId::new("encrypt_bytes", size),
                    &data,
                    |b, data| {
                        b.iter(|| {
                            black_box(key.encrypt_bytes_with_nonce(
                                black_box(data),
                                black_box(&associated_data),
                                black_box(Nonce::from_word(nonce_word)),
                            ))
                        });
                    },
                );

                // Decryption benchmark
                let encrypted = key.encrypt_bytes_with_nonce(
                    &data,
                    &associated_data,
                    Nonce::from_word(nonce_word),
                );

                group.bench_with_input(
                    BenchmarkId::new("decrypt_bytes", size),
                    &encrypted,
                    |b, encrypted| {
                        b.iter(|| {
                            black_box(
                                key.decrypt_bytes(black_box(encrypted), &associated_data).unwrap(),
                            )
                        });
                    },
                );
            }

            group.finish();
        }
    };
}

benchmark_aead_felts!("aead_rpo_felts", FELT_SIZES);
benchmark_aead_bytes!("aead_rpo_bytes", DATA_SIZES);

criterion_group!(aead_encryption_group, benchmark_aead_felts, benchmark_aead_bytes);
criterion_main!(aead_encryption_group);
