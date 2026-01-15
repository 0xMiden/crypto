# Merkle Mountain Range (MMR)

A Merkle Mountain Range (MMR) is a data structure designed to function as an append-only log. It allows efficient proofs of membership and consistency.

## Overview

MMR is a variant of a Merkle tree that supports efficient appending of new elements. Unlike standard Merkle trees, MMR doesn't require a power-of-two number of leaves, making it ideal for growing logs.

## Key Features

- **Append-only**: Efficiently add new elements
- **Membership proofs**: Prove that an element is in the MMR
- **Consistency proofs**: Prove consistency between different MMR states
- **Flexible size**: No requirement for power-of-two leaves

## Construction

### Creating an MMR

```rust
use miden_crypto::merkle::mmr::Mmr;

let mut mmr = Mmr::new();
```

### Appending Elements

```rust
use miden_crypto::Word;

let element1 = Word::new([/* ... */]);
let element2 = Word::new([/* ... */]);

mmr.add(element1);
mmr.add(element2);
```

## Accessing MMR Properties

### Getting the Peaks

```rust
let peaks = mmr.peaks();
```

### Getting the Forest Root

```rust
let forest_root = mmr.forest();
```

### Getting the Size

```rust
let size = mmr.forest().size();
```

## Proofs

### Membership Proof

```rust
use miden_crypto::merkle::mmr::{Mmr, MmrProof};

let mmr = Mmr::new();
// ... add elements ...

let index = 5; // Element index
let proof = mmr.open(index).unwrap();
let element = mmr.get(index).unwrap();

// Verify the proof
let peaks = mmr.peaks();
let is_valid = proof.verify(peaks, element, index);
```

### Consistency Proof

```rust
use miden_crypto::merkle::mmr::MmrDelta;

// Create delta between two MMR states
let delta = MmrDelta::new(old_mmr, new_mmr);

// Verify consistency
let is_consistent = delta.verify();
```

## Partial MMR

A `PartialMmr` provides a partial view of an MMR:

```rust
use miden_crypto::merkle::mmr::PartialMmr;

let partial = PartialMmr::new();
// Add known peaks and elements
partial.add_peak(peak);
partial.add_element(index, element);
```

## Use Cases

### Append-Only Logs

Perfect for maintaining an append-only log of events:

```rust
let mut log = Mmr::new();

// Add events
log.add(event1);
log.add(event2);
log.add(event3);

// Prove membership
let proof = log.open(1).unwrap();
```

### State Consistency

Prove that a new state is consistent with an old state:

```rust
let old_state = Mmr::new();
// ... populate old_state ...

let new_state = old_state.clone();
new_state.add(new_element);

let delta = MmrDelta::new(old_state, new_state);
assert!(delta.verify());
```

## Performance

- **Append**: O(log n) amortized
- **Proof generation**: O(log n)
- **Verification**: O(log n)

## Related

- [MerkleTree](merkle-tree.md): Standard Merkle tree
- [Merkle Trees Overview](overview.md)

