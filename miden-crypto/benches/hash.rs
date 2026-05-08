//! Simplified hash function benchmarks
//!
//! This module focuses on the two key operations across all hash functions:
//! 1. merge() - 2-to-1 hash merge (single permutation)
//! 2. hash_elements() - Sequential hashing of field elements (especially 100 elements)
//!
//! # Organization
//!
//! The benchmarks are organized by hash algorithm:
//! - RPO256
//! - RPX256
//! - Poseidon2
//! - Blake3 variants (256, 192, 160)
//! - Keccak256
//!
//! Each algorithm has two benchmarks:
//! - `hash_<algo>_merge` - 2-to-1 merge operation
//! - `hash_<algo>_sequential_felt` - Sequential hashing of field elements

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::hash::{
    HasherExt,
    blake::{Blake3_192, Blake3_256},
    keccak::Keccak256,
    poseidon2::{Poseidon2, Poseidon2Permutation256},
    rpo::{Rpo256, RpoPermutation256},
    rpx::{Rpx256, RpxPermutation256},
};
use p3_symmetric::Permutation;

// Import common utilities
mod common;
use common::data::{generate_byte_array_random, generate_felt_array_sequential};

// Import config constants
use crate::common::config::HASH_ELEMENT_COUNTS;

// === RPO256 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_rpo256_merge, "rpo256", |b: &mut criterion::Bencher| {
    let input1 = Rpo256::hash(&generate_byte_array_random(32));
    let input2 = Rpo256::hash(&generate_byte_array_random(32));
    b.iter(|| Rpo256::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
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

// === RPX256 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_rpx256_merge, "rpx256", |b: &mut criterion::Bencher| {
    let input1 = Rpx256::hash(&generate_byte_array_random(32));
    let input2 = Rpx256::hash(&generate_byte_array_random(32));
    b.iter(|| Rpx256::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
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

// === Poseidon2 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_poseidon2_merge, "poseidon2", |b: &mut criterion::Bencher| {
    let input1 = Poseidon2::hash(&generate_byte_array_random(32));
    let input2 = Poseidon2::hash(&generate_byte_array_random(32));
    b.iter(|| Poseidon2::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_poseidon2_sequential_felt,
    "poseidon2",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Poseidon2::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Blake3 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_blake3_merge, "blake3_256", |b: &mut criterion::Bencher| {
    let input1 = Blake3_256::hash(&generate_byte_array_random(32));
    let input2 = Blake3_256::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Blake3_256 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Blake3_256::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
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

// 2-to-1 hash merge
benchmark_hash_merge!(hash_blake3_192_merge, "blake3_192", |b: &mut criterion::Bencher| {
    let input1 = Blake3_192::hash(&generate_byte_array_random(32));
    let input2 = Blake3_192::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Blake3_192 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Blake3_192::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
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

// === Keccak256 benches ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_keccak_256_merge, "keccak_256", |b: &mut criterion::Bencher| {
    let input1 = Keccak256::hash(&generate_byte_array_random(32));
    let input2 = Keccak256::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Keccak256 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Keccak256::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
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

// === Scalar permutation dispatch (regression check) ===
//
// Each `*_permutation_scalar_dispatch` bench measures the cost of
// `Permutation<[Felt; STATE_WIDTH]>::permute_mut` when invoked through
// the new trait-generic blanket impl in `algebraic_sponge`. With the
// const-folded `if const { P::WIDTH == 1 }` fast-path, this should be
// byte-equivalent to the previous concrete `impl Permutation<[Felt;
// STATE_WIDTH]>` dispatch (which was a single `apply_permutation` call).
//
// Sister benches `*_apply_permutation_direct` call the inherent
// `apply_permutation` function bypassing the trait. Comparing the two
// within a single `cargo bench` run answers: did the trait-blanket
// extraction add measurable overhead to the scalar path?
//
// Expected outcome: the two should land within timing noise of each
// other (typically <1% difference). Any larger gap indicates the
// const-fold is not happening or some inlining barrier was introduced.
//
// To compare against the pre-blanket baseline directly, run this bench
// at HEAD~3 (before the trait-generic change) and at HEAD, then
// `cargo bench` numbers can be compared via criterion's saved baselines:
//   git checkout HEAD~3 -- miden-crypto/src/hash/algebraic_sponge
//   cargo bench --bench hash -- perm_rpo256 --save-baseline pre
//   git checkout HEAD -- miden-crypto/src/hash/algebraic_sponge
//   cargo bench --bench hash -- perm_rpo256 --baseline pre

fn perm_rpo256_scalar_dispatch(c: &mut Criterion) {
    let perm = RpoPermutation256;
    c.bench_function("perm_rpo256_scalar_dispatch", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| perm.permute_mut(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn perm_rpo256_apply_permutation_direct(c: &mut Criterion) {
    c.bench_function("perm_rpo256_apply_permutation_direct", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| RpoPermutation256::apply_permutation(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn perm_rpx256_scalar_dispatch(c: &mut Criterion) {
    let perm = RpxPermutation256;
    c.bench_function("perm_rpx256_scalar_dispatch", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| perm.permute_mut(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn perm_rpx256_apply_permutation_direct(c: &mut Criterion) {
    c.bench_function("perm_rpx256_apply_permutation_direct", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| RpxPermutation256::apply_permutation(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn perm_poseidon2_scalar_dispatch(c: &mut Criterion) {
    let perm = Poseidon2Permutation256;
    c.bench_function("perm_poseidon2_scalar_dispatch", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| perm.permute_mut(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn perm_poseidon2_apply_permutation_direct(c: &mut Criterion) {
    c.bench_function("perm_poseidon2_apply_permutation_direct", |b| {
        b.iter_batched(
            || generate_felt_array_sequential(12).try_into().unwrap(),
            |mut state: [_; 12]| Poseidon2Permutation256::apply_permutation(black_box(&mut state)),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    hash_benchmark_group,
    // RPO256 benchmarks
    hash_rpo256_merge,
    hash_rpo256_sequential_felt,
    // RPX256 benchmarks
    hash_rpx256_merge,
    hash_rpx256_sequential_felt,
    // Poseidon2 benchmarks
    hash_poseidon2_merge,
    hash_poseidon2_sequential_felt,
    // Blake3 benchmarks
    hash_blake3_merge,
    hash_blake3_sequential_felt,
    // Blake3_192 benchmarks
    hash_blake3_192_merge,
    hash_blake3_192_sequential_felt,
    // Keccak256 benchmarks
    hash_keccak_256_merge,
    hash_keccak_256_sequential_felt,
    // Scalar permutation dispatch — trait blanket vs direct inherent fn.
    perm_rpo256_scalar_dispatch,
    perm_rpo256_apply_permutation_direct,
    perm_rpx256_scalar_dispatch,
    perm_rpx256_apply_permutation_direct,
    perm_poseidon2_scalar_dispatch,
    perm_poseidon2_apply_permutation_direct,
);

criterion_main!(hash_benchmark_group);
