# Random Number Generation

Pseudo-random element generation for the Miden protocol context.

## Overview

The random number generation module provides traits and data structures for generating pseudo-random field elements and words in the context of the Miden protocol.

## Available Implementations

### RpoRandomCoin

Implements `FeltRng` and the `RandomCoin` trait using RPO hash function:

```rust
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Felt;

let mut coin = RpoRandomCoin::new(&[Felt::new(1), Felt::new(2)]);

// Draw random field elements
let element1 = coin.draw_element();
let element2 = coin.draw_element();

// Draw random words
let word = coin.draw_word();
```

### RpxRandomCoin

Implements `FeltRng` and the `RandomCoin` trait using RPX hash function:

```rust
use miden_crypto::rand::RpxRandomCoin;
use miden_crypto::Felt;

let mut coin = RpxRandomCoin::new(&[Felt::new(1), Felt::new(2)]);

// Draw random field elements
let element = coin.draw_element();
```

## Traits

### FeltRng

Trait for generating random field elements and words:

```rust
pub trait FeltRng: RngCore {
    fn draw_element(&mut self) -> Felt;
    fn draw_word(&mut self) -> Word;
}
```

### Randomizable

Trait for reading values from random bytes:

```rust
pub trait Randomizable: Sized {
    const VALUE_SIZE: usize;
    fn from_random_bytes(source: &[u8]) -> Option<Self>;
}
```

## Use Cases

- Fiat-Shamir transformation
- Random challenges in proof systems
- Random sampling in protocols
- Testing and benchmarking

## Related

- [RPO Random Coin](rpo-random-coin.md)
- [RPX Random Coin](rpx-random-coin.md)

