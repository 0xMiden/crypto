# MerkleTree

A fully-balanced binary Merkle tree where the number of leaves is a power of two. This is the standard Merkle tree structure used throughout Miden.

## Overview

`MerkleTree` is a simple, efficient implementation of a binary Merkle tree. It requires that the number of leaves is a power of two, ensuring the tree is fully balanced.

## Construction

### Creating a Tree

```rust
use miden_crypto::{merkle::MerkleTree, Word, Felt};

// Create leaves (must be a power of two)
let leaves = vec![
    Word::new([Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    Word::new([Felt::new(2), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    Word::new([Felt::new(3), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    Word::new([Felt::new(4), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
];

// Build the tree
let tree = MerkleTree::new(leaves).unwrap();
```

**Requirements:**
- Number of leaves must be at least 2
- Number of leaves must be a power of two

## Accessing Tree Properties

### Root

```rust
let root = tree.root();
```

### Depth

```rust
let depth = tree.depth();
// Depth 1 = 2 leaves, depth 2 = 4 leaves, etc.
```

### Getting a Node

```rust
use miden_crypto::merkle::NodeIndex;

let index = NodeIndex::new(depth, value).unwrap();
let node = tree.get_node(index).unwrap();
```

### Getting a Path

```rust
use miden_crypto::merkle::NodeIndex;

let index = NodeIndex::new(depth, leaf_index).unwrap();
let path = tree.get_path(index).unwrap();
```

## Iterating Over the Tree

### Leaves

```rust
for (index, leaf) in tree.leaves() {
    println!("Leaf {}: {:?}", index, leaf);
}
```

### Inner Nodes

```rust
for node_info in tree.inner_nodes() {
    println!("Node: {:?}", node_info);
}
```

## Updating Leaves

You can update individual leaves in the tree:

```rust
let mut tree = MerkleTree::new(leaves).unwrap();

// Update leaf at index 0
let new_leaf = Word::new([Felt::new(10), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
tree.update_leaf(0, new_leaf).unwrap();

// The root has changed
let new_root = tree.root();
```

## Merkle Proofs

### Creating a Proof

```rust
use miden_crypto::merkle::{MerkleTree, MerkleProof, NodeIndex};

let tree = MerkleTree::new(leaves).unwrap();
let index = NodeIndex::new(depth, leaf_index).unwrap();
let path = tree.get_path(index).unwrap();
let leaf = tree.get_node(index).unwrap();

let proof = MerkleProof::new(leaf, path);
```

### Verifying a Proof

```rust
let is_valid = proof.verify(root, index);
assert!(is_valid);
```

## Limitations

- **Fixed size**: The tree size is fixed at construction time
- **Power of two**: Number of leaves must be a power of two
- **Maximum depth**: Depth can be at most 64

## Performance

- **Construction**: O(n) where n is the number of leaves
- **Path retrieval**: O(log n)
- **Update**: O(log n)

## Use Cases

- Fixed-size commitments
- Batch verification of multiple values
- Standard Merkle tree applications
- When all leaves are known at construction time

## Related

- [MerkleStore](merkle-store.md): For storing multiple trees efficiently
- [PartialMerkleTree](partial-mt.md): For partial tree views
- [Merkle Trees Overview](overview.md)

