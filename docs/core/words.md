# Words

A `Word` is a unit of data consisting of 4 field elements (32 bytes total). Words are the fundamental data type in the Miden protocol.

## Overview

Words are used throughout Miden for:
- Hash function outputs (digests)
- Merkle tree nodes
- VM state
- Data commitments

## Usage

### Creating Words

```rust
use miden_crypto::{Word, Felt};

// From field elements
let word = Word::new([
    Felt::new(1),
    Felt::new(2),
    Felt::new(3),
    Felt::new(4),
]);

// Empty word
let empty = Word::default();

// From hex string
let word = Word::parse("0x1000000000000000200000000000000030000000000000004000000000000000").unwrap();
```

### Accessing Elements

```rust
// Index access
let first = word[0];
let second = word[1];

// Iteration
for element in word.iter() {
    println!("{:?}", element);
}
```

### Operations

```rust
// Comparison
assert_eq!(word1, word2);

// Conversion to bytes
let bytes: [u8; 32] = word.into();

// Conversion from bytes
let word = Word::from(bytes);
```

## Constants

- `EMPTY_WORD`: A word of all zeros
- `WORD_SIZE`: Number of field elements in a word (4)

## Serialization

Words can be serialized to/from bytes:

```rust
// Serialize
let bytes = word.to_bytes();

// Deserialize
let word = Word::from_bytes(bytes).unwrap();
```

## Related

- [Field Elements](field-elements.md): Individual field elements
- [Hash Functions](../hash/overview.md): Hash functions producing words

