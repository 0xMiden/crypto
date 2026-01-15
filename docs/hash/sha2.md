# SHA-2

SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash functions. Miden Crypto provides SHA-256 and SHA-512 implementations.

## Overview

SHA-2 is a widely-used standard hash function family. Miden Crypto implements:

- **SHA-256**: 256-bit output
- **SHA-512**: 512-bit output

## Usage

### SHA-256

```rust
use miden_crypto::hash::sha2::Sha256;

let data = b"Hello, Miden!";
let hash = Sha256::hash(data);
```

### SHA-512

```rust
use miden_crypto::hash::sha2::Sha512;

let data = b"Hello, Miden!";
let hash = Sha512::hash(data);
```

## When to Use SHA-2

Use SHA-2 when:

- You need maximum compatibility with existing systems
- You're working with systems that require SHA-2
- You need a standard, well-vetted hash function

## Related

- [Hash Functions Overview](overview.md)
- [BLAKE3](blake3.md)
- [Keccak256](keccak.md)

