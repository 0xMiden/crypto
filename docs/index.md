# Miden Crypto Documentation

Welcome to the Miden Crypto documentation! This library provides cryptographic primitives used in the [Polygon Miden](https://polygon.technology/miden) zero-knowledge virtual machine.

## Overview

The Miden Crypto library is a comprehensive collection of cryptographic primitives designed specifically for use in zero-knowledge proof systems, particularly STARKs (Scalable Transparent Arguments of Knowledge). The library provides:

- **Hash Functions**: Including algebraic hash functions optimized for STARKs (RPO, RPX, Poseidon2) and traditional hash functions (BLAKE3, Keccak, SHA-2)
- **Merkle Trees**: Various Merkle tree implementations including regular trees, Sparse Merkle Trees (SMT), Merkle Mountain Ranges (MMR), and large-scale storage-backed trees
- **Digital Signatures**: Multiple signature schemes including ECDSA, Ed25519, and RPO Falcon512
- **Encryption**: Authenticated encryption schemes optimized for both general use and STARK verification
- **Key Exchange**: Elliptic curve Diffie-Hellman implementations and integrated encryption schemes

## Target Audience

This documentation is designed for three main groups:

1. **Developers building on Polygon Miden**: Developers who want to write smart contracts (accounts, notes), build applications, and understand the underlying cryptographic primitives and their trade-offs
2. **Contributors to Polygon Miden**: Those interested in contributing to the cryptography or making proposals for improvements
3. **Users of Polygon Miden**: People who want to use Polygon Miden, including those who may want to participate in running the network

## Quick Start

### Installation

Add `miden-crypto` to your `Cargo.toml`:

```toml
[dependencies]
miden-crypto = "0.21"
```

### Basic Example

```rust
use miden_crypto::{hash::rpo::Rpo256, Felt, Word};

// Hash some data
let data = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Rpo256::hash_elements(&data);
println!("Hash: {:?}", hash);
```

## Key Features

### STARK-Optimized Primitives

Many primitives in this library are specifically designed for efficient execution within STARK proof systems:

- **RPO (Rescue Prime Optimized)**: An algebraic hash function that's highly efficient in STARKs
- **RPX (Rescue Prime Extended)**: A faster variant of RPO, approximately 2x faster
- **Poseidon2**: Another fast algebraic hash function, approximately 2x faster than RPX
- **AEAD-RPO**: Authenticated encryption optimized for STARK verification

### Flexible Architecture

The library supports both `std` and `no_std` environments:

- **Standard library**: Full-featured implementation with default features
- **No standard library**: WebAssembly-compatible builds for browser and embedded systems

### Performance Optimizations

- **AVX2/AVX-512 acceleration**: Hardware-accelerated hash functions on x86_64
- **SVE acceleration**: Hardware-accelerated hash functions on ARM64
- **Concurrent operations**: Multi-threaded implementations for multi-core systems
- **Storage-backed trees**: Large-scale Merkle trees backed by RocksDB for datasets exceeding memory

## Documentation Structure

- **[Getting Started](getting-started/overview.md)**: Installation and basic usage
- **[Hash Functions](hash/overview.md)**: All available hash functions
- **[Merkle Trees](merkle/overview.md)**: Tree data structures and their use cases
- **[Digital Signatures](dsa/overview.md)**: Signature schemes and key management
- **[Encryption](encryption/overview.md)**: Authenticated encryption schemes
- **[Key Exchange](key-exchange/overview.md)**: ECDH and integrated encryption
- **[Random Number Generation](rand/overview.md)**: Pseudo-random generators
- **[Core Types](core/field-elements.md)**: Field elements and words
- **[STARK Proving System](stark/overview.md)**: STARK-related components

## Resources

- [GitHub Repository](https://github.com/0xMiden/crypto)
- [Crates.io](https://crates.io/crates/miden-crypto)
- [Polygon Miden Documentation](https://docs.polygon.technology/miden)

## License

This project is dual-licensed under the [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE) licenses.

