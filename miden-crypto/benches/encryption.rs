use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_crypto::{
    Felt,
    encryption::{
        aes_gcm::{Nonce as AesNonce, SecretKey as AesSecretKey},
        rpo::{Nonce, SecretKey},
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Test data sizes in bytes
const DATA_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384, 65536, 262144];

// Field element data sizes
const FELT_SIZES: &[usize] = &[
    4,     // 32 bytes equivalent
    16,    // 128 bytes equivalent
    64,    // 512 bytes equivalent
    256,   // 2KB equivalent
    1024,  // 8KB equivalent
    4096,  // 32KB equivalent
    16384, // 128KB equivalent
];

fn bench_miden_encryption_felts(c: &mut Criterion) {
    let mut group = c.benchmark_group("miden_encryption_felts");

    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = (0..8).map(|_| Felt::new(rng.next_u64())).collect();

    for &size in FELT_SIZES {
        // Generate random field elements

        let data: Vec<Felt> = (0..size).map(|_| Felt::new(rng.next_u64())).collect();

        group.throughput(Throughput::Elements(size as u64));

        // Encryption benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                black_box(key.encrypt_with_nonce(
                    black_box(data),
                    black_box(&associated_data),
                    black_box(&nonce),
                ))
            });
        });

        // Decryption benchmark
        let encrypted = key.encrypt_with_nonce(&data, &associated_data, &nonce);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, encrypted| {
            b.iter(|| black_box(key.decrypt(black_box(encrypted), black_box(&nonce)).unwrap()));
        });
    }

    group.finish();
}

fn bench_miden_encryption_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("miden_encryption_bytes");

    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let mut associated_data = vec![0_u8; 8];
    rng.fill_bytes(&mut associated_data);

    for &size in DATA_SIZES {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        group.throughput(Throughput::Bytes(size as u64));

        // Encryption benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                black_box(key.encrypt_bytes_with_nonce(
                    black_box(data),
                    black_box(&associated_data),
                    black_box(&nonce),
                ))
            });
        });

        // Decryption benchmark
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, &nonce);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, encrypted| {
            b.iter(|| {
                black_box(key.decrypt_bytes(black_box(encrypted), black_box(&nonce)).unwrap())
            });
        });
    }

    group.finish();
}

fn bench_aes_gcm_encryption_felts(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encryption_felts");
    use aes_gcm::aead::{OsRng, rand_core::RngCore};

    let mut rng = OsRng;
    let key = AesSecretKey::with_rng(&mut rng);
    let nonce = AesNonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = (0..8).map(|_| Felt::new(rng.next_u64())).collect();

    for &size in FELT_SIZES {
        // Generate random field elements

        let data: Vec<Felt> = (0..size).map(|_| Felt::new(rng.next_u64())).collect();

        group.throughput(Throughput::Elements(size as u64));

        // Encryption benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                black_box(key.encrypt_with_nonce(
                    black_box(data),
                    black_box(&associated_data),
                    black_box(&nonce),
                ))
            });
        });

        // Decryption benchmark
        let encrypted = key.encrypt_with_nonce(&data, &associated_data, &nonce);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, encrypted| {
            b.iter(|| black_box(key.decrypt(black_box(encrypted), black_box(&nonce)).unwrap()));
        });
    }

    group.finish();
}

fn bench_aes_gcm_encryption_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encryption_bytes");
    use aes_gcm::aead::{OsRng, rand_core::RngCore};

    let mut rng = OsRng;
    let key = AesSecretKey::with_rng(&mut rng);
    let nonce = AesNonce::with_rng(&mut rng);

    let mut associated_data = vec![0_u8; 8];
    rng.fill_bytes(&mut associated_data);

    for &size in DATA_SIZES {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        group.throughput(Throughput::Bytes(size as u64));

        // Encryption benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                black_box(key.encrypt_bytes_with_nonce(
                    black_box(data),
                    black_box(&associated_data),
                    black_box(&nonce),
                ))
            });
        });

        // Decryption benchmark
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, &nonce);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, encrypted| {
            b.iter(|| {
                black_box(key.decrypt_bytes(black_box(encrypted), black_box(&nonce)).unwrap())
            });
        });
    }

    group.finish();
}

criterion_group!(
    encryption_group,
    bench_miden_encryption_felts,
    bench_miden_encryption_bytes,
    bench_aes_gcm_encryption_felts,
    bench_aes_gcm_encryption_bytes
);

criterion_main!(encryption_group);
