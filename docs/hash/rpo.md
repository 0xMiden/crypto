# RPO (Rescue Prime Optimized)

RPO (Rescue Prime Optimized) is the primary algebraic hash function used in Miden. It is specifically designed to be highly efficient when executed within STARK proof systems.

## Overview

RPO is implemented according to the [Rescue Prime Optimized specifications](https://eprint.iacr.org/2022/1577) with padding rules from the [RPX specification](https://eprint.iacr.org/2023/1045).

## Parameters

- **Field**: 64-bit prime field with modulus p = 2^64 - 2^32 + 1 (Goldilocks field)
- **State width**: 12 field elements
- **Rate size**: 8 field elements
- **Capacity size**: 4 field elements
- **Number of rounds**: 7
- **S-Box degree**: 7
- **Security level**: 128 bits
- **Output size**: 256 bits (4 field elements, 32 bytes)

## Usage

### Basic Hashing

```rust
use miden_crypto::{hash::rpo::Rpo256, Felt};

// Hash field elements
let elements = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Rpo256::hash_elements(&elements);

// Hash bytes
let data = b"Hello, Miden!";
let hash = Rpo256::hash(data);
```

### Merging Digests

For Merkle tree construction:

```rust
use miden_crypto::{hash::rpo::Rpo256, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);

// Merge two digests
let merged = Rpo256::merge(&[digest1, digest2]);

// Merge multiple digests
let digests = vec![digest1, digest2, /* ... */];
let merged = Rpo256::merge_many(&digests);
```

### Merging with Integer

```rust
use miden_crypto::{hash::rpo::Rpo256, Word, Felt};

let seed = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let value = 42u64;

let hash = Rpo256::merge_with_int(seed, value);
```

### Domain Separation

For applications that need to hash in different domains:

```rust
use miden_crypto::{hash::rpo::Rpo256, Word, Felt};

let digest1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
let digest2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
let domain = Felt::new(123);

let hash = Rpo256::merge_in_domain(&[digest1, digest2], domain);
```

## Hash Output Consistency

The following functions are internally consistent:

- `hash_elements()`: Hashes field elements directly
- `merge()`: Merges two digests
- `merge_with_int()`: Merges a digest with an integer

These functions will always produce the same result for the same inputs. For example, merging two digests using `merge()` produces the same result as hashing the 8 elements that make up those digests using `hash_elements()`.

However, `hash()` is **not** consistent with the above functions. It's designed for arbitrary binary strings and uses different padding/deserialization. If your data consists of valid field elements, use `hash_elements()` instead.

## Empty Input

Empty input is hashed to the zero digest `[0, 0, 0, 0]`. This avoids unnecessary permutation calls when hashing empty data.

## Security

RPO targets a **128-bit security level**:

- Collision resistance: 128 bits
- Pre-image resistance: 128 bits (degraded by log₂(domain_size) when using domain separation)
- Second pre-image resistance: 128 bits

Domain separation degrades pre-image resistance by the logarithm of the domain identifier space size. The 128-bit security level is maintained as long as the domain identifier space (including padding) is less than 2^128.

## Performance

RPO is optimized for STARK verification. For raw performance benchmarks, see the [benchmarks](https://github.com/0xMiden/crypto/tree/main/miden-crypto/benches).

The implementation supports hardware acceleration:

- **AVX2**: On x86_64 platforms with AVX2 support
- **AVX-512**: On x86_64 platforms with AVX-512 support
- **SVE**: On ARM64 platforms with SVE support

## API Reference

### Constants

- `COLLISION_RESISTANCE`: Target collision resistance level (128 bits)
- `NUM_ROUNDS`: Number of rounds (7)
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

- [RPX Hash](rpx.md): Faster variant of RPO
- [Poseidon2 Hash](poseidon2.md): Another fast algebraic hash function
- [Hash Functions Overview](overview.md)

