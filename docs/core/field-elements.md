# Field Elements

Field elements in Miden Crypto are represented by the `Felt` type, which is an alias for the Goldilocks field element.

## Overview

The Goldilocks field is a 64-bit prime field with modulus p = 2^64 - 2^32 + 1. This field is optimized for efficient arithmetic operations in zero-knowledge proof systems.

## Usage

### Creating Field Elements

```rust
use miden_crypto::Felt;

// Constants
let zero = Felt::ZERO;
let one = Felt::ONE;

// From u64
let value = Felt::new(42);

// From bytes
let bytes = [0u8; 8];
let felt = Felt::from_bytes(bytes);
```

### Operations

```rust
let a = Felt::new(10);
let b = Felt::new(20);

// Arithmetic
let sum = a + b;
let product = a * b;
let difference = a - b;
let quotient = a / b;

// Comparisons
assert!(a < b);
assert_eq!(a, Felt::new(10));
```

### Serialization

```rust
// To bytes
let bytes: [u8; 8] = felt.to_bytes();

// To hex string
let hex = format!("{:?}", felt);
```

## Constants

- `ZERO`: The zero element
- `ONE`: The multiplicative identity
- `WORD_SIZE`: Number of field elements in a word (4)

## Related

- [Words](words.md): Collections of 4 field elements
- [Hash Functions](../hash/overview.md): Hash functions operating on field elements

