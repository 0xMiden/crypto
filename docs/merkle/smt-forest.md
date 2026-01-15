# SmtForest

A collection of Sparse Merkle Trees with depth 64, designed to efficiently store trees with common subtrees. Similar to `MerkleStore` but for SMTs.

## Overview

`SmtForest` allows multiple SMTs to share common subtrees, significantly reducing memory usage when storing multiple tree versions.

## Key Features

- **Shared subtrees**: Common nodes are stored only once
- **Multiple trees**: Store multiple SMT versions efficiently
- **Pruning**: Remove old unused trees
- **Efficient updates**: Update trees without duplicating unchanged nodes

## Construction

```rust
use miden_crypto::merkle::smt::SmtForest;

let mut forest = SmtForest::new();
```

## Operations

### Adding Trees

```rust
let tree_id = forest.add_tree().unwrap();

// Insert entries into the tree
forest.insert(tree_id, key, value).unwrap();
```

### Getting Values

```rust
let value = forest.get(tree_id, &key).unwrap();
```

### Getting Root

```rust
let root = forest.root(tree_id).unwrap();
```

### Pruning

Remove old unused trees:

```rust
forest.prune(old_tree_id).unwrap();
```

## Use Cases

### Version Control

Store multiple versions of an SMT efficiently:

```rust
let mut forest = SmtForest::new();

// Create version 1
let v1 = forest.add_tree().unwrap();
forest.insert(v1, key1, value1).unwrap();

// Create version 2 (shares common nodes)
let v2 = forest.add_tree().unwrap();
forest.insert(v2, key1, value1).unwrap(); // Same as v1
forest.insert(v2, key2, value2).unwrap(); // New entry

// Both trees share common nodes
```

### Efficient State Management

Manage multiple state trees with shared history:

```rust
// Create base state
let base = forest.add_tree().unwrap();
// ... populate base ...

// Create derived state (shares nodes with base)
let derived = forest.add_tree().unwrap();
// ... populate derived ...

// Prune old states when no longer needed
forest.prune(base).unwrap();
```

## Performance

- **Memory efficiency**: Common nodes stored only once
- **Fast lookups**: O(log n) for value retrieval
- **Scalable**: Efficient for multiple tree versions

## Related

- [MerkleStore](merkle-store.md): Similar concept for standard Merkle trees
- [Smt](smt.md): Individual SMT implementation
- [Merkle Trees Overview](overview.md)

