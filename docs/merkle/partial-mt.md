# PartialMerkleTree

A partial view of a Merkle tree where some sub-trees may not be known. This is similar to a collection of Merkle paths all resolving to the same root.

## Overview

`PartialMerkleTree` allows you to work with a Merkle tree when you only have partial knowledge of its structure. It's useful when you receive Merkle paths from different sources and need to combine them or verify them against a known root.

## Key Features

- **Partial knowledge**: Work with trees when not all nodes are known
- **Path collection**: Collect multiple Merkle paths
- **Root verification**: Verify paths against a known root
- **Flexible depth**: Supports paths up to depth 64

## Construction

### Creating a Partial Tree

```rust
use miden_crypto::merkle::PartialMerkleTree;

let mut partial = PartialMerkleTree::new();
```

### Adding Paths

```rust
use miden_crypto::merkle::{MerklePath, NodeIndex};

let path = MerklePath::new(/* ... */);
let index = NodeIndex::new(depth, leaf_index).unwrap();
let leaf = Word::new([/* ... */]);

partial.add_path(index, leaf, path).unwrap();
```

## Accessing Properties

### Getting the Root

```rust
let root = partial.root();
```

### Getting a Path

```rust
let index = NodeIndex::new(depth, leaf_index).unwrap();
let path = partial.get_path(index).unwrap();
```

### Checking if Path Exists

```rust
let exists = partial.has_path(index);
```

## Use Cases

### Combining Proofs

Combine Merkle paths from different sources:

```rust
let mut partial = PartialMerkleTree::new();

// Add paths from different sources
partial.add_path(index1, leaf1, path1).unwrap();
partial.add_path(index2, leaf2, path2).unwrap();

// Get the combined root
let root = partial.root();
```

### Verifying Against Known Root

Verify that partial paths are consistent with a known root:

```rust
let known_root = Word::new([/* ... */]);
let computed_root = partial.root();

assert_eq!(computed_root, known_root);
```

## Limitations

- **Maximum depth**: Path length can be at most 64
- **Partial information**: Some operations may fail if required nodes are missing

## Related

- [MerkleTree](merkle-tree.md): Full Merkle tree
- [MerklePath](merkle-tree.md#merkle-proofs): Merkle path structure
- [Merkle Trees Overview](overview.md)

