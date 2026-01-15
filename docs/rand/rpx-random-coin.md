# RpxRandomCoin

A random coin implementation using the RPX hash function. Implements both `FeltRng` and the `RandomCoin` trait.

## Usage

```rust
use miden_crypto::rand::RpxRandomCoin;
use miden_crypto::Felt;

// Initialize with seed
let mut coin = RpxRandomCoin::new(&[Felt::new(1), Felt::new(2)]);

// Draw random field elements
let element = coin.draw_element();
```

## Related

- [Random Number Generation Overview](overview.md)

