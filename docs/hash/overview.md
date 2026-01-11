# Hash Functions Overview

Miden Crypto provides a comprehensive set of cryptographic hash functions designed for different use cases. The library includes both algebraic hash functions optimized for STARK proof systems and traditional hash functions for general-purpose use.

## Hash Function Categories

### Algebraic Hash Functions (STARK-Optimized)

These hash functions are designed to be highly efficient when executed within STARK proof systems:

- **[RPO (Rescue Prime Optimized)](rpo.md)**: The primary algebraic hash function used throughout Miden
- **[RPX (Rescue Prime Extended)](rpx.md)**: A faster variant of RPO, approximately 2x faster
- **[Poseidon2](poseidon2.md)**: Another fast algebraic hash function, approximately 2x faster than RPX

### Traditional Hash Functions

These are standard cryptographic hash functions for general-purpose use:

- **[BLAKE3](blake3.md)**: Modern hash function with 256-bit, 192-bit, or 160-bit output
- **[Keccak256](keccak.md)**: SHA-3 family hash function with 256-bit output
- **[SHA-2](sha2.md)**: SHA-256 and SHA-512 implementations

## Choosing a Hash Function

### For STARK Proof Systems

When building applications that will be verified in STARKs, use algebraic hash functions:

1. **Poseidon2**: Fastest option, best for new applications
2. **RPX**: Good balance of speed and compatibility
3. **RPO**: Most widely used in Miden, best for compatibility

### For General-Purpose Use

For applications outside of STARK verification:

- **BLAKE3**: Best general-purpose choice, very fast
- **Keccak256**: Good for Ethereum compatibility
- **SHA-2**: Standard choice for maximum compatibility

## Common Operations

All hash functions in Miden Crypto support similar operations:

### Hashing Field Elements

```rust
use miden_crypto::{hash::rpo::Rpo256, Felt};

let elements = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Rpo256::hash_elements(&elements);
```

### Hashing Bytes

```rust
use miden_crypto::hash::rpo::Rpo256;

let data = b"Hello, Miden!";
let hash = Rpo256::hash(data);
```

### Merging Digests

For Merkle tree construction:

```rust
use miden_crypto::{hash::rpo::Rpo256, Word};

let digest1 = Word::new([/* ... */]);
let digest2 = Word::new([/* ... */]);
let merged = Rpo256::merge(&[digest1, digest2]);
```

## Hash Output Consistency

**Important**: When working with field elements, use `hash_elements()` rather than `hash()` for consistency. The `hash()` function is designed for arbitrary binary strings and may produce different results for the same field elements.

For example:

```rust
// ✅ Consistent - use hash_elements for field elements
let elements = [Felt::new(1), Felt::new(2)];
let hash1 = Rpo256::hash_elements(&elements);

// ❌ May produce different results
let bytes = /* serialize elements */;
let hash2 = Rpo256::hash(&bytes);
// hash1 != hash2 in general
```

## Security Properties

All hash functions in Miden Crypto target a **128-bit security level**:

- **Collision resistance**: 128 bits
- **Pre-image resistance**: 128 bits
- **Second pre-image resistance**: 128 bits

## Performance

For performance benchmarks comparing these hash functions, see the [benchmarks directory](https://github.com/0xMiden/crypto/tree/main/miden-crypto/benches).

## Next Steps

- [RPO Hash](rpo.md): Learn about the primary STARK-optimized hash function
- [RPX Hash](rpx.md): Learn about the faster RPO variant
- [Poseidon2 Hash](poseidon2.md): Learn about the fastest algebraic hash function
- [BLAKE3](blake3.md): Learn about the general-purpose hash function

