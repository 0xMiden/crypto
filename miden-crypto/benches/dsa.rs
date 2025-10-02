//! Comprehensive Digital Signature Algorithm (DSA) benchmarks
//!
//! This module benchmarks all DSA operations implemented in the library
//! with a focus on the RPO-Falcon512 signature scheme.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Key generation operations
//! 2. Signing operations (with and without RNG)
//! 3. Verification operations
//! 4. Hash-to-point conversions
//! 5. Polynomial operations
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
    dsa::rpo_falcon512::{PublicKey, SecretKey, Signature},
};
use rand::rng;

// Import hash-to-point functions
// hash_to_point_rpo256 will be called directly from the benchmark

// Import common utilities
mod common;
use common::*;

// Import configuration constants
use crate::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE};

/// Configuration for key generation benchmarks
const KEYGEN_ITERATIONS: usize = 10;

// === Key Generation Benchmarks ===

// Secret key generation without RNG
benchmark_with_setup! {
    dsa_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "generate",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = SecretKey::new();
        })
    },
}

// Secret key generation with custom RNG
benchmark_with_setup_data! {
    dsa_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "generate_with_rng",
    || {

        rng()
    },
    |b: &mut criterion::Bencher, rng: &rand::rngs::ThreadRng| {
        b.iter(|| {
            let mut rng_clone = rng.clone();
            let _secret_key = SecretKey::with_rng(&mut rng_clone);
        })
    },
}

// Public key generation from secret key
benchmark_with_setup_data! {
    dsa_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "generate_from_secret",
    || {
        let secret_keys: Vec<SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| SecretKey::new()).collect();
        secret_keys
    },
    |b: &mut criterion::Bencher, secret_keys: &Vec<SecretKey>| {
        b.iter(|| {
            for secret_key in secret_keys {
                let _public_key = secret_key.public_key();
            }
        })
    },
}

// === Signing Benchmarks ===

// Message signing without RNG
benchmark_with_setup_data! {
    dsa_sign_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sign_messages",
    || {
        let secret_keys: Vec<SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| SecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        (secret_keys, messages)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages): &(Vec<SecretKey>, Vec<Word>)| {
        b.iter(|| {
            for (secret_key, message) in secret_keys.iter().zip(messages.iter()) {
                let _signature = secret_key.sign(black_box(*message));
            }
        })
    },
}

// Message signing with custom RNG
benchmark_with_setup_data! {
    dsa_sign_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sign_messages_with_rng",
    || {
        let secret_keys: Vec<SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| SecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let rngs: Vec<_> = (0..KEYGEN_ITERATIONS).map(|_| rng()).collect();
        (secret_keys, messages, rngs)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages, rngs): &(Vec<SecretKey>, Vec<Word>, Vec<_>)| {
        b.iter(|| {
            let mut rngs_local = rngs.clone();
            for ((secret_key, message), rng) in
                secret_keys.iter().zip(messages.iter()).zip(rngs_local.iter_mut())
            {
                let _signature = secret_key.sign_with_rng(black_box(*message), rng);
            }
        })
    },
}

// === Verification Benchmarks ===

// Signature verification
benchmark_with_setup_data! {
    dsa_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "verify_signatures",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_keys: Vec<SecretKey> =
            (0..KEYGEN_ITERATIONS).map(|_| SecretKey::with_rng(&mut rng)).collect();
        let public_keys: Vec<PublicKey> = secret_keys.iter().map(|sk| sk.public_key()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let signatures: Vec<Signature> = secret_keys
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign_with_rng(black_box(*msg), &mut rng))
            .collect();
        (public_keys, messages, signatures)
    },
    |b: &mut criterion::Bencher, (public_keys, messages, signatures): &(Vec<PublicKey>, Vec<Word>, Vec<Signature>)| {
        b.iter(|| {
            for ((public_key, message), signature) in
                public_keys.iter().zip(messages.iter()).zip(signatures.iter())
            {
                let _result = public_key.verify(black_box(*message), signature);
            }
        })
    },
}

// === Benchmark Group Configuration ===

criterion_group!(
    dsa_benchmark_group,
    // Key generation benchmarks
    dsa_keygen_secret_default,
    dsa_keygen_secret_with_rng,
    dsa_keygen_public,
    // Signing benchmarks
    dsa_sign_default,
    dsa_sign_with_rng,
    // Verification benchmarks
    dsa_verify,
);

criterion_main!(dsa_benchmark_group);
