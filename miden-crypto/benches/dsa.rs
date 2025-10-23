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
        ecdsa_k256_keccak, eddsa_25519,
        rpo_falcon512::{self, PublicKey as RpoPublicKey, SecretKey as RpoSecretKey},
    },
};
use rand::rng;

// Import common utilities
mod common;
use common::*;

// Import configuration constants
use crate::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE};

/// Configuration for key generation benchmarks
const KEYGEN_ITERATIONS: usize = 10;

// ================================================================================================
// RPO-FALCON512 BENCHMARKS
// ================================================================================================

// === Key Generation Benchmarks ===

// Secret key generation without RNG
benchmark_with_setup! {
    rpo_falcon512_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_keygen_secret",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = RpoSecretKey::new();
        })
    },
}

// Secret key generation with custom RNG
benchmark_with_setup_data! {
    rpo_falcon512_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_keygen_secret_with_rng",
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
    rpo_falcon512_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_keygen_public",
    || {
        let secret_keys: Vec<RpoSecretKey> = (0..KEYGEN_ITERATIONS).map(|_| RpoSecretKey::new()).collect();
        secret_keys
    },
    |b: &mut criterion::Bencher, secret_keys: &Vec<RpoSecretKey>| {
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
    rpo_falcon512_sign_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_sign",
    || {
        let secret_keys: Vec<RpoSecretKey> = (0..KEYGEN_ITERATIONS).map(|_| RpoSecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        (secret_keys, messages)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages): &(Vec<RpoSecretKey>, Vec<Word>)| {
        b.iter(|| {
            for (secret_key, message) in secret_keys.iter().zip(messages.iter()) {
                let _signature = secret_key.sign(black_box(*message));
            }
        })
    },
}

// Message signing with custom RNG
benchmark_with_setup_data! {
    rpo_falcon512_sign_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_sign_with_rng",
    || {
        let secret_keys: Vec<RpoSecretKey> = (0..KEYGEN_ITERATIONS).map(|_| RpoSecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let rngs: Vec<_> = (0..KEYGEN_ITERATIONS).map(|_| rng()).collect();
        (secret_keys, messages, rngs)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages, rngs): &(Vec<RpoSecretKey>, Vec<Word>, Vec<_>)| {
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
    rpo_falcon512_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "rpo_falcon512_verify",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_keys: Vec<RpoSecretKey> =
            (0..KEYGEN_ITERATIONS).map(|_| RpoSecretKey::with_rng(&mut rng)).collect();
        let public_keys: Vec<RpoPublicKey> = secret_keys.iter().map(|sk| sk.public_key()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let signatures: Vec<rpo_falcon512::Signature> = secret_keys
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign_with_rng(black_box(*msg), &mut rng))
            .collect();
        (public_keys, messages, signatures)
    },
    |b: &mut criterion::Bencher, (public_keys, messages, signatures): &(Vec<RpoPublicKey>, Vec<Word>, Vec<rpo_falcon512::Signature>)| {
        b.iter(|| {
            for ((public_key, message), signature) in
                public_keys.iter().zip(messages.iter()).zip(signatures.iter())
            {
                let _result = public_key.verify(black_box(*message), signature);
            }
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
        let secret_keys: Vec<ecdsa_k256_keccak::SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| ecdsa_k256_keccak::SecretKey::new()).collect();
        secret_keys
    },
    |b: &mut criterion::Bencher, secret_keys: &Vec<ecdsa_k256_keccak::SecretKey>| {
        b.iter(|| {
            for secret_key in secret_keys {
                let _public_key = secret_key.public_key();
            }
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
        let secret_keys: Vec<ecdsa_k256_keccak::SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| ecdsa_k256_keccak::SecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        (secret_keys, messages)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages): &(Vec<ecdsa_k256_keccak::SecretKey>, Vec<Word>)| {
        b.iter(|| {
            // Clone secret keys since sign() needs &mut self
            let mut secret_keys_local = secret_keys.clone();
            for (secret_key, message) in secret_keys_local.iter_mut().zip(messages.iter()) {
                let _signature = secret_key.sign(black_box(*message));
            }
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
        let mut secret_keys: Vec<ecdsa_k256_keccak::SecretKey> =
            (0..KEYGEN_ITERATIONS).map(|_| ecdsa_k256_keccak::SecretKey::with_rng(&mut rng)).collect();
        let public_keys: Vec<ecdsa_k256_keccak::PublicKey> = secret_keys.iter().map(|sk| sk.public_key()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let signatures: Vec<ecdsa_k256_keccak::Signature> = secret_keys
            .iter_mut()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign(black_box(*msg)))
            .collect();
        (public_keys, messages, signatures)
    },
    |b: &mut criterion::Bencher, (public_keys, messages, signatures): &(Vec<ecdsa_k256_keccak::PublicKey>, Vec<Word>, Vec<ecdsa_k256_keccak::Signature>)| {
        b.iter(|| {
            for ((public_key, message), signature) in
                public_keys.iter().zip(messages.iter()).zip(signatures.iter())
            {
                let _result = public_key.verify(black_box(*message), signature);
            }
        })
    },
}

// ================================================================================================
// EDDSA 25519 BENCHMARKS
// ================================================================================================

// === Key Generation Benchmarks ===

benchmark_with_setup! {
    eddsa_25519_keygen_secret_default,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_keygen_secret",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            let _secret_key = eddsa_25519::SecretKey::new();
        })
    },
}

benchmark_with_setup_data! {
    eddsa_25519_keygen_secret_with_rng,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_keygen_secret_with_rng",
    || {
        rng()
    },
    |b: &mut criterion::Bencher, rng: &rand::rngs::ThreadRng| {
        b.iter(|| {
            let mut rng_clone = rng.clone();
            let _secret_key = eddsa_25519::SecretKey::with_rng(&mut rng_clone);
        })
    },
}

benchmark_with_setup_data! {
    eddsa_25519_keygen_public,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_keygen_public",
    || {
        let secret_keys: Vec<eddsa_25519::SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| eddsa_25519::SecretKey::new()).collect();
        secret_keys
    },
    |b: &mut criterion::Bencher, secret_keys: &Vec<eddsa_25519::SecretKey>| {
        b.iter(|| {
            for secret_key in secret_keys {
                let _public_key = secret_key.public_key();
            }
        })
    },
}

// === Signing Benchmarks ===

benchmark_with_setup_data! {
    eddsa_25519_sign,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_sign",
    || {
        let secret_keys: Vec<eddsa_25519::SecretKey> = (0..KEYGEN_ITERATIONS).map(|_| eddsa_25519::SecretKey::new()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        (secret_keys, messages)
    },
    |b: &mut criterion::Bencher, (secret_keys, messages): &(Vec<eddsa_25519::SecretKey>, Vec<Word>)| {
        b.iter(|| {
            for (secret_key, message) in secret_keys.iter().zip(messages.iter()) {
                let _signature = secret_key.sign(black_box(*message));
            }
        })
    },
}

// === Verification Benchmarks ===

benchmark_with_setup_data! {
    eddsa_25519_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eddsa_25519_verify",
    || {
        let mut rng = rand::rngs::ThreadRng::default();
        let secret_keys: Vec<eddsa_25519::SecretKey> =
            (0..KEYGEN_ITERATIONS).map(|_| eddsa_25519::SecretKey::with_rng(&mut rng)).collect();
        let public_keys: Vec<eddsa_25519::PublicKey> = secret_keys.iter().map(|sk| sk.public_key()).collect();
        let messages: Vec<Word> =
            (0..KEYGEN_ITERATIONS).map(|i| Word::new([Felt::new(i as u64); 4])).collect();
        let signatures: Vec<eddsa_25519::Signature> = secret_keys
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign(black_box(*msg)))
            .collect();
        (public_keys, messages, signatures)
    },
    |b: &mut criterion::Bencher, (public_keys, messages, signatures): &(Vec<eddsa_25519::PublicKey>, Vec<Word>, Vec<eddsa_25519::Signature>)| {
        b.iter(|| {
            for ((public_key, message), signature) in
                public_keys.iter().zip(messages.iter()).zip(signatures.iter())
            {
                let _result = public_key.verify(black_box(*message), signature);
            }
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
    eddsa_25519_keygen_secret_default,
    eddsa_25519_keygen_secret_with_rng,
    eddsa_25519_keygen_public,
    eddsa_25519_sign,
    eddsa_25519_verify,
    // RPO-Falcon512 benchmarks
    rpo_falcon512_keygen_secret_default,
    rpo_falcon512_keygen_secret_with_rng,
    rpo_falcon512_keygen_public,
    rpo_falcon512_sign_default,
    rpo_falcon512_sign_with_rng,
    rpo_falcon512_verify,
);

criterion_main!(dsa_benchmark_group);
