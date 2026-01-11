# Overview

Miden Crypto is a cryptographic library designed for the Polygon Miden zero-knowledge virtual machine. It provides a comprehensive set of cryptographic primitives optimized for use in STARK proof systems.

## What is Miden Crypto?

Miden Crypto provides:

- **Hash Functions**: Both algebraic (STARK-optimized) and traditional hash functions
- **Merkle Trees**: Various tree structures for efficient data commitments
- **Digital Signatures**: Multiple signature schemes for authentication
- **Encryption**: Authenticated encryption for data confidentiality
- **Key Exchange**: Secure key agreement protocols
- **Random Number Generation**: Pseudo-random generators for field elements

## Design Philosophy

The library is designed with the following principles:

1. **STARK Efficiency**: Many primitives are optimized for efficient execution within STARK proof systems
2. **Flexibility**: Supports both `std` and `no_std` environments
3. **Performance**: Hardware acceleration and concurrent operations where applicable
4. **Security**: Modern cryptographic primitives with strong security guarantees

## When to Use Miden Crypto

Use Miden Crypto when you need:

- Cryptographic primitives for Polygon Miden applications
- Hash functions optimized for zero-knowledge proofs
- Merkle tree structures for data commitments
- Signature schemes compatible with Miden VM
- Encryption schemes that can be efficiently verified in STARKs

## Next Steps

- [Installation](installation.md): Learn how to add Miden Crypto to your project
- [Basic Usage](basic-usage.md): See examples of common operations

