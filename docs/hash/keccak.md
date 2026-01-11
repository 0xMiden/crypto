# Keccak256

Keccak256 is a cryptographic hash function from the SHA-3 family. It provides 256-bit output and is widely used, particularly in Ethereum-compatible systems.

## Overview

Keccak256 follows the [Keccak specifications](https://keccak.team/specifications.html). It's the hash function used in Ethereum and many other blockchain systems.

## Usage

```rust
use miden_crypto::hash::keccak::Keccak256;

let data = b"Hello, Miden!";
let hash = Keccak256::hash(data);
```

## When to Use Keccak256

Use Keccak256 when:

- You need Ethereum compatibility
- You're working with Ethereum-based systems
- You need a standard, widely-adopted hash function

## Related

- [Hash Functions Overview](overview.md)
- [BLAKE3](blake3.md)
- [SHA-2](sha2.md)

