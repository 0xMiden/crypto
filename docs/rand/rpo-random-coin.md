# RpoRandomCoin

A random coin implementation using the RPO hash function. Implements both `FeltRng` and the `RandomCoin` trait.

## Usage

```rust
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Felt;

// Initialize with seed
let mut coin = RpoRandomCoin::new(&[Felt::new(1), Felt::new(2)]);

// Draw random field elements
let element1 = coin.draw_element();
let element2 = coin.draw_element();

// Draw random words (4 field elements)
let word = coin.draw_word();
```

## Related

- [Random Number Generation Overview](overview.md)

