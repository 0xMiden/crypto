# BLAKE3

BLAKE3 is a modern cryptographic hash function that provides excellent performance for general-purpose hashing. Miden Crypto supports BLAKE3 with 256-bit, 192-bit, and 160-bit output sizes.

## Overview

BLAKE3 is based on the [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3). The 192-bit and 160-bit outputs are obtained by truncating the standard 256-bit output.

## Usage

### 256-bit Output

```rust
use miden_crypto::hash::blake::Blake3_256;

let data = b"Hello, Miden!";
let hash = Blake3_256::hash(data);
```

### 192-bit Output

```rust
use miden_crypto::hash::blake::Blake3_192;

let data = b"Hello, Miden!";
let hash = Blake3_192::hash(data);
```

### 160-bit Output

```rust
use miden_crypto::hash::blake::Blake3_160;

let data = b"Hello, Miden!";
let hash = Blake3_160::hash(data);
```

## When to Use BLAKE3

Use BLAKE3 when:

- You need a fast, general-purpose hash function
- You're not constrained by STARK verification requirements
- You need compatibility with standard hash functions
- You need different output sizes (192-bit, 160-bit)

## Performance

BLAKE3 is one of the fastest general-purpose hash functions available. It's significantly faster than SHA-2 and provides better security properties than older hash functions.

## Related

- [Hash Functions Overview](overview.md)
- [Keccak256](keccak.md)
- [SHA-2](sha2.md)

