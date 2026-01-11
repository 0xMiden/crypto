//! Comprehensive Digital Signature Algorithm (DSA) benchmarks
//!
//! This module benchmarks all DSA operations implemented in the library:
//! - RPO-Falcon512 (Falcon using RPO for hashing)
//! - ECDSA over secp256k1 (using Keccak for hashing)
//! - EdDSA (Ed25519 using SHA-512)
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Key generation operations
//! 2. Signing operations (with and without RNG)
//! 3. Verification operations
//!
//! # Adding New DSA Benchmarks
//!
//! To add benchmarks for new DSA algorithms:
//! 1. Add the algorithm to the imports
//! 2. Add parameterized benchmark functions following the naming convention
//! 3. Add to the appropriate benchmark group
//! 4. Update input size arrays in config.rs if needed

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
// Import DSA modules
use miden_crypto::{
    Felt, Word,
    dsa::{
        ecdsa_k256_keccak, eddsa_25519_sha512,
        falcon512_rpo::{self, PublicKey as RpoPublicKey, SecretKey as RpoSecretKey},
    },
};
use rand::rng;

// Import common utilities
mod common;
use common::*;

// Import configuration constants
use crate::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE};

// ================================================================================================
// RPO-FALCON512 BENCHMARKS
// ================================================================================================

// === Key Generation Benchmarks ===

// Secret key generation without RNG
benchmark_with_setup! {
    falcon512_rpo_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_keygen_secret",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = RpoSecretKey::new();
        })
    },
}

// Secret key generation with custom RNG
benchmark_with_setup_data! {
    falcon512_rpo_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_keygen_secret_with_rng",
    || {
        rng()
    },
    |b: &mut criterion::Bencher, rng: &rand::rngs::ThreadRng| {
        b.iter(|| {
            let mut rng_clone = rng.clone();
            let _secret_key = RpoSecretKey::with_rng(&mut rng_clone);
        })
    },
}

// Public key generation from secret key
benchmark_with_setup_data! {
    falcon512_rpo_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_keygen_public",
    || {
        RpoSecretKey::new()
    },
    |b: &mut criterion::Bencher, secret_key: &RpoSecretKey| {
        b.iter(|| {
            let _public_key = secret_key.public_key();
        })
    },
}

// === Signing Benchmarks ===

// Message signing without RNG
benchmark_with_setup_data! {
    falcon512_rpo_sign_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_sign",
    || {
        let secret_key = RpoSecretKey::new();
        secret_key
    },
    |b: &mut criterion::Bencher, secret_key: &RpoSecretKey| {
        let mut counter = 0u64;
        b.iter(|| {
            // Use a different message each iteration to get varied random sequences
            // and measure representative performance across different rejection sampling paths
            let message = Word::new([Felt::new(counter); 4]);
            counter = counter.wrapping_add(1);
            let _signature = secret_key.sign(black_box(message));
        })
    },
}

// Message signing with custom RNG
benchmark_with_setup_data! {
    falcon512_rpo_sign_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_sign_with_rng",
    || {
        let secret_key = RpoSecretKey::new();
        let rng = rng();
        (secret_key, rng)
    },
    |b: &mut criterion::Bencher, (secret_key, rng): &(RpoSecretKey, rand::rngs::ThreadRng)| {
        let mut counter = 0u64;
        b.iter(|| {
            // Use a different message each iteration to get varied random sequences
            let message = Word::new([Felt::new(counter); 4]);
            counter = counter.wrapping_add(1);
            let mut rng_clone = rng.clone();
            let _signature = secret_key.sign_with_rng(black_box(message), &mut rng_clone);
        })
    },
}

// === Verification Benchmarks ===

// Signature verification
benchmark_with_setup_data! {
    falcon512_rpo_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "falcon512_rpo_verify",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_key = RpoSecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let message = Word::new([Felt::new(42); 4]);
        let signature = secret_key.sign_with_rng(black_box(message), &mut rng);
        (public_key, message, signature)
    },
    |b: &mut criterion::Bencher, (public_key, message, signature): &(RpoPublicKey, Word, falcon512_rpo::Signature)| {
        b.iter(|| {
            let _result = public_key.verify(black_box(*message), signature);
        })
    },
}

// ================================================================================================
// ECDSA K256 BENCHMARKS (using Keccak)
// ================================================================================================

// === Key Generation Benchmarks ===

benchmark_with_setup! {
    ecdsa_k256_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "ecdsa_k256_keygen_secret",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = ecdsa_k256_keccak::SecretKey::new();
        })
    },
}

benchmark_with_setup_data! {
    ecdsa_k256_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "ecdsa_k256_keygen_secret_with_rng",
    || {
        rng()
    },
    |b: &mut criterion::Bencher, rng: &rand::rngs::ThreadRng| {
        b.iter(|| {
            let mut rng_clone = rng.clone();
            let _secret_key = ecdsa_k256_keccak::SecretKey::with_rng(&mut rng_clone);
        })
    },
}

benchmark_with_setup_data! {
    ecdsa_k256_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "ecdsa_k256_keygen_public",
    || {
        ecdsa_k256_keccak::SecretKey::new()
    },
    |b: &mut criterion::Bencher, secret_key: &ecdsa_k256_keccak::SecretKey| {
        b.iter(|| {
            let _public_key = secret_key.public_key();
        })
    },
}

// === Signing Benchmarks ===

benchmark_with_setup_data! {
    ecdsa_k256_sign,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "ecdsa_k256_sign",
    || {
        ecdsa_k256_keccak::SecretKey::new()
    },
    |b: &mut criterion::Bencher, secret_key: &ecdsa_k256_keccak::SecretKey| {
        let mut counter = 0u64;
        b.iter(|| {
            // Clone secret key since sign() needs &mut self
            let secret_key_local = secret_key.clone();
            // Use a different message each iteration for representative performance
            let message = Word::new([Felt::new(counter); 4]);
            counter = counter.wrapping_add(1);
            let _signature = secret_key_local.sign(black_box(message));
        })
    },
}

// === Verification Benchmarks ===

benchmark_with_setup_data! {
    ecdsa_k256_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "ecdsa_k256_verify",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_key = ecdsa_k256_keccak::SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let message = Word::new([Felt::new(42); 4]);
        let signature = secret_key.sign(black_box(message));
        (public_key, message, signature)
    },
    |b: &mut criterion::Bencher, (public_key, message, signature): &(ecdsa_k256_keccak::PublicKey, Word, ecdsa_k256_keccak::Signature)| {
        b.iter(|| {
            let _result = public_key.verify(black_box(*message), signature);
        })
    },
}

// ================================================================================================
// EDDSA 25519 BENCHMARKS
// ================================================================================================

// === Key Generation Benchmarks ===

benchmark_with_setup! {
    eddsa_25519_sha512_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sha512_keygen_secret",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = eddsa_25519_sha512::SecretKey::new();
        })
    },
}

benchmark_with_setup_data! {
    eddsa_25519_sha512_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sha512_keygen_secret_with_rng",
    || {
        rng()
    },
    |b: &mut criterion::Bencher, rng: &rand::rngs::ThreadRng| {
        b.iter(|| {
            let mut rng_clone = rng.clone();
            let _secret_key = eddsa_25519_sha512::SecretKey::with_rng(&mut rng_clone);
        })
    },
}

benchmark_with_setup_data! {
    eddsa_25519_sha512_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sha512_keygen_public",
    || {
        eddsa_25519_sha512::SecretKey::new()
    },
    |b: &mut criterion::Bencher, secret_key: &eddsa_25519_sha512::SecretKey| {
        b.iter(|| {
            let _public_key = secret_key.public_key();
        })
    },
}

// === Signing Benchmarks ===

benchmark_with_setup_data! {
    eddsa_25519_sha512_sign,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sha512_sign",
    || {
        eddsa_25519_sha512::SecretKey::new()
    },
    |b: &mut criterion::Bencher, secret_key: &eddsa_25519_sha512::SecretKey| {
        let mut counter = 0u64;
        b.iter(|| {
            // Use a different message each iteration for representative performance
            let message = Word::new([Felt::new(counter); 4]);
            counter = counter.wrapping_add(1);
            let _signature = secret_key.sign(black_box(message));
        })
    },
}

// === Verification Benchmarks ===

benchmark_with_setup_data! {
    eddsa_25519_sha512_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sha512_verify",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_key = eddsa_25519_sha512::SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let message = Word::new([Felt::new(42); 4]);
        let signature = secret_key.sign(black_box(message));
        (public_key, message, signature)
    },
    |b: &mut criterion::Bencher, (public_key, message, signature): &(eddsa_25519_sha512::PublicKey, Word, eddsa_25519_sha512::Signature)| {
        b.iter(|| {
            let _result = public_key.verify(black_box(*message), signature);
        })
    },
}

// ================================================================================================
// BENCHMARK GROUP CONFIGURATION
// ================================================================================================

criterion_group!(
    dsa_benchmark_group,
    // ECDSA k256 benchmarks
    ecdsa_k256_keygen_secret_default,
    ecdsa_k256_keygen_secret_with_rng,
    ecdsa_k256_keygen_public,
    ecdsa_k256_sign,
    ecdsa_k256_verify,
    // EdDSA 25519 benchmarks
    eddsa_25519_sha512_keygen_secret_default,
    eddsa_25519_sha512_keygen_secret_with_rng,
    eddsa_25519_sha512_keygen_public,
    eddsa_25519_sha512_sign,
    eddsa_25519_sha512_verify,
    // RPO-Falcon512 benchmarks
    falcon512_rpo_keygen_secret_default,
    falcon512_rpo_keygen_secret_with_rng,
    falcon512_rpo_keygen_public,
    falcon512_rpo_sign_default,
    falcon512_rpo_sign_with_rng,
    falcon512_rpo_verify,
);

criterion_main!(dsa_benchmark_group);
