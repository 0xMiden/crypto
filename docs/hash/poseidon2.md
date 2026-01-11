# Poseidon2

Poseidon2 is a fast algebraic hash function designed for zero-knowledge proof systems. It is approximately **2x faster than RPX** and **4x faster than RPO**, making it the fastest algebraic hash function in Miden Crypto.

## Overview

Poseidon2 follows the original [specification](https://eprint.iacr.org/2023/323) and is based on the [reference implementation](https://github.com/HorizenLabs/poseidon2).

## Parameters

- **Field**: 64-bit prime field with modulus 2^64 - 2^32 + 1 (Goldilocks field)
- **State width**: 12 field elements
- **Rate size**: 8 field elements
- **Capacity size**: 4 field elements
- **S-Box degree**: 7
- **Rounds**: Mixed structure with 2 types of rounds:
  - **Initial External (IE)**: `add_constants` → `apply_sbox` → `apply_matmul_external`
  - **Internal**: `add_constants` → `apply_sbox` → `apply_matmul_internal` (only first state element)
  - **Terminal External (TE)**: `add_constants` → `apply_sbox` → `apply_matmul_external`
  - An additional `apply_matmul_external` is applied at the beginning for security
- **Security level**: 128 bits
- **Output size**: 256 bits (4 field elements, 32 bytes)

## Usage

### Using the Hasher Interface

```rust
use miden_crypto::{hash::poseidon2::Poseidon2Hasher, Felt};

let mut hasher = Poseidon2Hasher::new();

// Update with field elements
hasher.update(&[Felt::new(1), Felt::new(2), Felt::new(3)]);

// Finalize to get the hash
let hash = hasher.finalize();
```

### Using Static Methods

```rust
use miden_crypto::{hash::poseidon2::Poseidon2, Felt};

// Hash field elements
let elements = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Poseidon2::hash_elements(&elements);

// Hash bytes
let data = b"Hello, Miden!";
let hash = Poseidon2::hash(data);
```

### Merging Digests

```rust
use miden_crypto::{hash::poseidon2::Poseidon2, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);

// Merge two digests
let merged = Poseidon2::merge(&[digest1, digest2]);

// Merge multiple digests
let digests = vec![digest1, digest2, /* ... */];
let merged = Poseidon2::merge_many(&digests);
```

### Merging with Integer

```rust
use miden_crypto::{hash::poseidon2::Poseidon2, Word, Felt};

let seed = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let value = 42u64;

let hash = Poseidon2::merge_with_int(seed, value);
```

### Domain Separation

```rust
use miden_crypto::{hash::poseidon2::Poseidon2, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
let domain = Felt::new(123);

let hash = Poseidon2::merge_in_domain(&[digest1, digest2], domain);
```

## Hash Output Consistency

Like RPO and RPX, the following functions are internally consistent:

- `hash_elements()`: Hashes field elements directly
- `merge()`: Merges two digests
- `merge_with_int()`: Merges a digest with an integer

The `hash()` function is **not** consistent with these functions. Use `hash_elements()` when working with field elements.

## Empty Input

Empty input is hashed to the zero digest `[0, 0, 0, 0]`.

## Security

Poseidon2 targets a **128-bit security level**:

- Collision resistance: 128 bits
- Pre-image resistance: 128 bits (degraded by log₂(domain_size) when using domain separation)
- Second pre-image resistance: 128 bits

## Performance

Poseidon2 is the **fastest** algebraic hash function in Miden Crypto:

- Approximately **2x faster** than RPX
- Approximately **4x faster** than RPO

This makes it the best choice for new applications that prioritize performance.

## When to Use Poseidon2

Use Poseidon2 when:

- You need the fastest algebraic hash function
- You're building new applications (not constrained by existing RPO/RPX usage)
- Performance is a critical concern

## API Reference

### Hasher Interface

- `Poseidon2Hasher::new() -> Self`: Create a new hasher
- `update(&mut self, elements: &[Felt])`: Update hasher with field elements
- `finalize(self) -> Word`: Finalize and get the hash

### Static Methods

- `hash(bytes: &[u8]) -> Word`: Hash arbitrary bytes
- `hash_elements(elements: &[E]) -> Word`: Hash field elements
- `merge(values: &[Word; 2]) -> Word`: Merge two digests
- `merge_many(values: &[Word]) -> Word`: Merge multiple digests
- `merge_with_int(seed: Word, value: u64) -> Word`: Merge digest with integer
- `merge_in_domain(values: &[Word; 2], domain: Felt) -> Word`: Merge with domain separation

### Compression Function

- `Poseidon2Compression`: Compression function for use in Merkle trees

### Challenger

- `Poseidon2Challenger`: Fiat-Shamir challenger using Poseidon2

## Related

- [RPO Hash](rpo.md): The original Rescue Prime Optimized hash function
- [RPX Hash](rpx.md): Faster variant of RPO
- [Hash Functions Overview](overview.md)

