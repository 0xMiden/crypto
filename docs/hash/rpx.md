# RPX (Rescue Prime Extended)

RPX (Rescue Prime Extended) is a faster variant of RPO, approximately **2x faster** than RPO while maintaining the same security properties.

## Overview

RPX is based on the XHash12 construction from the [RPX specifications](https://eprint.iacr.org/2023/1045). It uses a different permutation structure than RPO to achieve better performance.

## Parameters

- **Field**: 64-bit prime field with modulus 2^64 - 2^32 + 1 (Goldilocks field)
- **State width**: 12 field elements
- **Rate size**: 8 field elements
- **Capacity size**: 4 field elements
- **S-Box degree**: 7
- **Rounds**: Mixed structure with 3 types of rounds:
  - **(FB)**: Full round with forward and inverse S-box
  - **(E)**: Extension round using degree 3 extension field
  - **(M)**: Matrix-only round
  - **Permutation**: (FB) (E) (FB) (E) (FB) (E) (M)
- **Security level**: 128 bits
- **Output size**: 256 bits (4 field elements, 32 bytes)

## Usage

### Basic Hashing

```rust
use miden_crypto::{hash::rpx::Rpx256, Felt};

// Hash field elements
let elements = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Rpx256::hash_elements(&elements);

// Hash bytes
let data = b"Hello, Miden!";
let hash = Rpx256::hash(data);
```

### Merging Digests

```rust
use miden_crypto::{hash::rpx::Rpx256, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);

// Merge two digests
let merged = Rpx256::merge(&[digest1, digest2]);

// Merge multiple digests
let digests = vec![digest1, digest2, /* ... */];
let merged = Rpx256::merge_many(&digests);
```

### Merging with Integer

```rust
use miden_crypto::{hash::rpx::Rpx256, Word, Felt};

let seed = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let value = 42u64;

let hash = Rpx256::merge_with_int(seed, value);
```

### Domain Separation

```rust
use miden_crypto::{hash::rpx::Rpx256, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
let domain = Felt::new(123);

let hash = Rpx256::merge_in_domain(&[digest1, digest2], domain);
```

## Hash Output Consistency

Like RPO, the following functions are internally consistent:

- `hash_elements()`: Hashes field elements directly
- `merge()`: Merges two digests
- `merge_with_int()`: Merges a digest with an integer

The `hash()` function is **not** consistent with these functions. Use `hash_elements()` when working with field elements.

## Empty Input

Empty input is hashed to the zero digest `[0, 0, 0, 0]`.

## Security

RPX targets a **128-bit security level**, identical to RPO:

- Collision resistance: 128 bits
- Pre-image resistance: 128 bits (degraded by log₂(domain_size) when using domain separation)
- Second pre-image resistance: 128 bits

## Performance

RPX is approximately **2x faster** than RPO while maintaining the same security properties. This makes it an excellent choice for applications that prioritize performance.

The implementation supports the same hardware acceleration as RPO:

- **AVX2**: On x86_64 platforms with AVX2 support
- **AVX-512**: On x86_64 platforms with AVX-512 support
- **SVE**: On ARM64 platforms with SVE support

## When to Use RPX

Use RPX when:

- You need better performance than RPO
- You want compatibility with RPO's API
- You're building new applications (not constrained by existing RPO usage)

## API Reference

### Constants

- `COLLISION_RESISTANCE`: Target collision resistance level (128 bits)
- `STATE_WIDTH`: Sponge state width (12 elements)
- `RATE_RANGE`: Range of rate elements (4-11)
- `CAPACITY_RANGE`: Range of capacity elements (0-3)
- `DIGEST_RANGE`: Range of digest elements (4-7)

### Methods

- `hash(bytes: &[u8]) -> Word`: Hash arbitrary bytes
- `hash_elements(elements: &[E]) -> Word`: Hash field elements
- `merge(values: &[Word; 2]) -> Word`: Merge two digests
- `merge_many(values: &[Word]) -> Word`: Merge multiple digests
- `merge_with_int(seed: Word, value: u64) -> Word`: Merge digest with integer
- `merge_in_domain(values: &[Word; 2], domain: Felt) -> Word`: Merge with domain separation

## Related

- [RPO Hash](rpo.md): The original Rescue Prime Optimized hash function
- [Poseidon2 Hash](poseidon2.md): Another fast algebraic hash function
- [Hash Functions Overview](overview.md)

