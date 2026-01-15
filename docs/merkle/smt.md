# Sparse Merkle Trees (SMT)

Sparse Merkle Trees (SMT) are key-value data structures that support efficient proofs of membership and non-membership. Miden Crypto provides several SMT implementations for different use cases.

## Overview

A Sparse Merkle Tree is a key-value map that also supports proving that a given value is stored at a given key. The tree is viewed as always being fully populated - if a leaf's value was not explicitly set, it stores a default value.

## Available Implementations

### SimpleSmt

A simple SMT with no compaction, mapping 64-bit keys to 4-element values:

```rust
use miden_crypto::merkle::smt::SimpleSmt;

let mut smt = SimpleSmt::new();

// Insert key-value pair
let key = 42u64;
let value = Word::new([/* ... */]);
smt.insert(key, value).unwrap();

// Get value
let retrieved = smt.get(key).unwrap();

// Get root
let root = smt.root();
```

### Smt

A SMT with compaction at depth 64, mapping 4-element keys to 4-element values:

```rust
use miden_crypto::merkle::smt::Smt;

let mut smt = Smt::new();

// Insert key-value pair
let key = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
let value = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];
smt.insert(key, value);

// Get value
let retrieved = smt.get(&key);

// Get root
let root = smt.root();
```

## Operations

### Insertion

```rust
smt.insert(key, value);
```

### Lookup

```rust
let value = smt.get(&key);
```

### Updates

```rust
smt.update(key, new_value);
```

### Deletion

```rust
smt.remove(&key);
```

## Proofs

### Creating a Proof

```rust
use miden_crypto::merkle::smt::SmtProof;

let proof = smt.prove(&key).unwrap();
```

### Verifying a Proof

```rust
let is_valid = proof.verify(root, key, value);
```

## Batch Operations

### Batch Construction

```rust
use miden_crypto::merkle::smt::Smt;

let entries = vec![
    (key1, value1),
    (key2, value2),
    // ...
];

let smt = Smt::with_entries(entries).unwrap();
```

## Performance

- **Insertion**: O(log n)
- **Lookup**: O(log n)
- **Proof generation**: O(log n)
- **Verification**: O(log n)

With the `concurrent` feature enabled, batch operations can use multiple threads for better performance.

## Use Cases

### Key-Value Store

Use SMT as a key-value store with cryptographic proofs:

```rust
let mut store = Smt::new();

// Store data
store.insert(key, value);

// Prove membership
let proof = store.prove(&key).unwrap();
```

### State Commitments

Commit to a state and prove individual values:

```rust
// Commit to state
let root = smt.root();

// Prove a value is in the state
let proof = smt.prove(&key).unwrap();
```

## Related

- [LargeSmt](large-smt.md): For very large datasets
- [SmtForest](smt-forest.md): For multiple SMTs
- [Merkle Trees Overview](overview.md)

