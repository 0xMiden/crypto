//! Comprehensive hash function benchmarks
//!
//! This module benchmarks all hash functions implemented in the library
//! using parameterized benchmarks for efficient input size testing.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Hash algorithm (RPO256, RPX256, Blake3, Keccak256)
//! 2. Operation type (single hash, 2-to-1 merge, sequential)
//! 3. Parameterized input sizes using BenchmarkGroup
//!
//! # Adding New Hash Benchmarks
//!
//! To add benchmarks for a new hash algorithm:
//! 1. Add the algorithm to the imports
//! 2. Add parameterized benchmark functions
//! 3. Add to the appropriate benchmark group
//! 4. Update input size arrays in config.rs if needed

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt,
    hash::{
        blake::{Blake3_160, Blake3_192, Blake3_256},
        keccak::Keccak256,
        rpo::Rpo256,
        rpx::Rpx256,
    },
};
use winter_crypto::Hasher;

// Import common utilities
mod common;
use common::data::{
    generate_byte_array_random, generate_byte_array_sequential, generate_felt_array_sequential,
};

// Import config constants
use crate::common::config::{
    HASH_ELEMENT_COUNTS, HASH_INPUT_SIZES, MERGE_INPUT_SIZES, MERGE_INT_SIZES,
};

// === RPO256 Hash Benchmarks ===

// Single hash operation with parameterized input sizes
benchmark_hash!(
    hash_rpo256_single,
    "rpo256",
    "single",
    HASH_INPUT_SIZES,
    |b: &mut criterion::Bencher, size| {
        let data = generate_byte_array_sequential(size);
        b.iter(|| Rpo256::hash(black_box(&data)))
    },
    size,
    |size| Some(criterion::Throughput::Bytes(size as u64))
);

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_rpo256_merge,
    "rpo256",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Rpo256::hash(&generate_byte_array_random(size));
        let input2 = Rpo256::hash(&generate_byte_array_random(size));
        b.iter(|| Rpo256::merge(black_box(&[input1, input2])))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_rpo256_sequential_felt,
    "rpo256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Rpo256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// Domain-separated merging with parameterized inputs
benchmark_hash_merge_domain!(
    hash_rpo256_merge_in_domain,
    "rpo256",
    MERGE_INPUT_SIZES,
    &[0u64, 1, u64::MAX],
    |b: &mut criterion::Bencher, (size, domain)| {
        let data = generate_byte_array_sequential(size);
        let digest = Rpo256::hash(&data);
        let domain_felt = Felt::new(domain);
        b.iter(|| Rpo256::merge_in_domain(black_box(&[digest, digest]), domain_felt))
    }
);

// Merging with integers of various sizes
benchmark_hash_merge_with_int!(
    hash_rpo256_merge_with_int,
    "rpo256",
    &[32, 64, 256],
    MERGE_INT_SIZES,
    |b: &mut criterion::Bencher, (size, _int_size)| {
        let data = generate_byte_array_sequential(size);
        let digest = Rpo256::hash(&data);
        // Use zero as the integer value since we're testing merge operation performance,
        // not the specific integer value being merged.
        let int = 0u64;
        b.iter(|| Rpo256::merge_with_int(black_box(digest), int))
    }
);

// Multi-digest merging with parameterized digest counts
benchmark_hash_merge_many!(
    hash_rpo256_merge_many,
    "rpo256",
    &[1, 2],
    |b: &mut criterion::Bencher, digest_count| {
        let mut digests = Vec::new();
        for _ in 0..digest_count {
            let data = generate_byte_array_sequential(64);
            digests.push(Rpo256::hash(&data));
        }
        b.iter(|| Rpo256::merge_many(black_box(&digests)))
    }
);

// === RPX256 Hash Benchmarks ===

// Single hash operation with parameterized input sizes
benchmark_hash!(
    hash_rpx256_single,
    "rpx256",
    "single",
    HASH_INPUT_SIZES,
    |b: &mut criterion::Bencher, size| {
        let data = generate_byte_array_sequential(size);
        b.iter(|| Rpx256::hash(black_box(&data)))
    },
    size,
    |size| Some(criterion::Throughput::Bytes(size as u64))
);

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_rpx256_merge,
    "rpx256",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Rpx256::hash(&generate_byte_array_random(size));
        let input2 = Rpx256::hash(&generate_byte_array_random(size));
        b.iter(|| Rpx256::merge(black_box(&[input1, input2])))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_rpx256_sequential_felt,
    "rpx256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Rpx256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// Domain-separated merging with parameterized inputs
benchmark_hash_merge_domain!(
    hash_rpx256_merge_in_domain,
    "rpx256",
    MERGE_INPUT_SIZES,
    &[0u64, 1, u64::MAX],
    |b: &mut criterion::Bencher, (size, domain)| {
        let data = generate_byte_array_sequential(size);
        let digest = Rpx256::hash(&data);
        let domain_felt = Felt::new(domain);
        b.iter(|| Rpx256::merge_in_domain(black_box(&[digest, digest]), domain_felt))
    }
);

// Merging with integers of various sizes
benchmark_hash_merge_with_int!(
    hash_rpx256_merge_with_int,
    "rpx256",
    &[32, 64, 256],
    MERGE_INT_SIZES,
    |b: &mut criterion::Bencher, (size, _int_size)| {
        let data = generate_byte_array_sequential(size);
        let digest = Rpx256::hash(&data);
        // Use zero as the integer value since we're testing merge operation performance,
        // not the specific integer value being merged.
        let int = 0u64;
        b.iter(|| Rpx256::merge_with_int(black_box(digest), int))
    }
);

// Multi-digest merging with parameterized digest counts
benchmark_hash_merge_many!(
    hash_rpx256_merge_many,
    "rpx256",
    &[1, 2],
    |b: &mut criterion::Bencher, digest_count| {
        let mut digests = Vec::new();
        for _ in 0..digest_count {
            let data = generate_byte_array_sequential(64);
            digests.push(Rpx256::hash(&data));
        }
        b.iter(|| Rpx256::merge_many(black_box(&digests)))
    }
);

// === Blake3 Hash Benchmarks ===

// Single hash operation with parameterized input sizes
benchmark_hash!(
    hash_blake3_single,
    "blake3_256",
    "single",
    HASH_INPUT_SIZES,
    |b: &mut criterion::Bencher, size| {
        let data = generate_byte_array_sequential(size);
        b.iter(|| Blake3_256::hash(black_box(&data)))
    },
    size,
    |size| Some(criterion::Throughput::Bytes(size as u64))
);

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_blake3_merge,
    "blake3_256",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Blake3_256::hash(&generate_byte_array_random(size));
        let input2 = Blake3_256::hash(&generate_byte_array_random(size));
        let digest_inputs: [<Blake3_256 as Hasher>::Digest; 2] = [input1, input2];
        b.iter(|| Blake3_256::merge(black_box(&digest_inputs)))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_blake3_sequential_felt,
    "blake3_256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Blake3_256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Blake3_192 Hash Benchmarks ===

// Single hash operation with parameterized input sizes
benchmark_hash!(
    hash_blake3_192_single,
    "blake3_192",
    "single",
    HASH_INPUT_SIZES,
    |b: &mut criterion::Bencher, size| {
        let data = generate_byte_array_sequential(size);
        b.iter(|| Blake3_192::hash(black_box(&data)))
    },
    size,
    |size| Some(criterion::Throughput::Bytes(size as u64))
);

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_blake3_192_merge,
    "blake3_192",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Blake3_192::hash(&generate_byte_array_random(size));
        let input2 = Blake3_192::hash(&generate_byte_array_random(size));
        let digest_inputs: [<Blake3_192 as Hasher>::Digest; 2] = [input1, input2];
        b.iter(|| Blake3_192::merge(black_box(&digest_inputs)))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_blake3_192_sequential_felt,
    "blake3_192",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Blake3_192::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Blake3_160 Hash Benchmarks ===

// Single hash operation with parameterized input sizes
benchmark_hash!(
    hash_blake3_160_single,
    "blake3_160",
    "single",
    HASH_INPUT_SIZES,
    |b: &mut criterion::Bencher, size| {
        let data = generate_byte_array_sequential(size);
        b.iter(|| Blake3_160::hash(black_box(&data)))
    },
    size,
    |size| Some(criterion::Throughput::Bytes(size as u64))
);

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_blake3_160_merge,
    "blake3_160",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Blake3_160::hash(&generate_byte_array_random(size));
        let input2 = Blake3_160::hash(&generate_byte_array_random(size));
        let digest_inputs: [<Blake3_160 as Hasher>::Digest; 2] = [input1, input2];
        b.iter(|| Blake3_160::merge(black_box(&digest_inputs)))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_blake3_160_sequential_felt,
    "blake3_160",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Blake3_160::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Keccak256 benches ===

// 2-to-1 hash merge with parameterized inputs
benchmark_hash_merge!(
    hash_keccak_256_merge,
    "keccak_256",
    &[32, 64, 256],
    |b: &mut criterion::Bencher, size| {
        let input1 = Keccak256::hash(&generate_byte_array_random(size));
        let input2 = Keccak256::hash(&generate_byte_array_random(size));
        let digest_inputs: [<Keccak256 as Hasher>::Digest; 2] = [input1, input2];
        b.iter(|| Keccak256::merge(black_box(&digest_inputs)))
    }
);

// Sequential hashing of Felt elements with parameterized counts
benchmark_hash_felt!(
    hash_keccak_256_sequential_felt,
    "keccak_256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Keccak256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

criterion_group!(
    hash_benchmark_group,
    // RPO256 benchmarks
    hash_rpo256_single,
    hash_rpo256_merge,
    hash_rpo256_sequential_felt,
    hash_rpo256_merge_in_domain,
    hash_rpo256_merge_with_int,
    hash_rpo256_merge_many,
    // RPX256 benchmarks
    hash_rpx256_single,
    hash_rpx256_merge,
    hash_rpx256_sequential_felt,
    hash_rpx256_merge_in_domain,
    hash_rpx256_merge_with_int,
    hash_rpx256_merge_many,
    // Blake3 benchmarks
    hash_blake3_single,
    hash_blake3_merge,
    hash_blake3_sequential_felt,
    // Blake3_192 benchmarks
    hash_blake3_192_single,
    hash_blake3_192_merge,
    hash_blake3_192_sequential_felt,
    // Blake3_160 benchmarks
    hash_blake3_160_single,
    hash_blake3_160_merge,
    hash_blake3_160_sequential_felt,
    // Keccak256 benchmarks
    hash_keccak_256_merge,
    hash_keccak_256_sequential_felt,
);

criterion_main!(hash_benchmark_group);
