# MerkleStore

A collection of Merkle trees designed to efficiently store trees with common subtrees. This allows multiple tree versions to share common nodes, significantly reducing memory usage.

## Overview

`MerkleStore` is an in-memory data store for Merkle trees that allows all nodes of multiple trees to live as long as necessary without duplication. This enables space-efficient persistent data structures.

## Key Features

- **Shared nodes**: Common subtrees are stored only once
- **Multiple trees**: Store multiple tree versions efficiently
- **Efficient updates**: Update trees without duplicating unchanged nodes
- **Path retrieval**: Get paths from any stored tree by root

## Construction

### Creating a Store

```rust
use miden_crypto::merkle::store::MerkleStore;

let mut store = MerkleStore::new();
```

The store is initialized with the SMT empty nodes (255 nodes for depth 64).

## Adding Trees

### Adding a Complete Tree

```rust
use miden_crypto::merkle::{MerkleTree, store::MerkleStore};

let tree1 = MerkleTree::new(leaves1).unwrap();
let tree2 = MerkleTree::new(leaves2).unwrap();

// Add trees to the store
store.extend(tree1.inner_nodes());
store.extend(tree2.inner_nodes());
```

### Adding Individual Nodes

```rust
use miden_crypto::merkle::{InnerNodeInfo, store::MerkleStore};

let node_info = InnerNodeInfo {
    value: node_value,
    left: left_child,
    right: right_child,
};

store.set_node(node_info);
```

## Accessing Nodes

### Getting a Node

```rust
use miden_crypto::merkle::{NodeIndex, store::MerkleStore};

let root = tree.root();
let index = NodeIndex::new(depth, value).unwrap();
let node = store.get_node(root, index).unwrap();
```

### Getting a Path

```rust
use miden_crypto::merkle::{NodeIndex, store::MerkleStore};

let root = tree.root();
let index = NodeIndex::new(depth, leaf_index).unwrap();
let path = store.get_path(root, index).unwrap();
```

## Querying the Store

### Number of Internal Nodes

```rust
let count = store.num_internal_nodes();
```

### Checking if a Node Exists

```rust
let exists = store.has_node(node_value);
```

### Getting All Roots

```rust
let roots = store.get_roots();
```

## Use Cases

### Version Control

Store multiple versions of a tree efficiently:

```rust
// Create initial tree
let tree_v1 = MerkleTree::new(leaves_v1).unwrap();
store.extend(tree_v1.inner_nodes());

// Create updated tree (shares most nodes)
let tree_v2 = MerkleTree::new(leaves_v2).unwrap();
store.extend(tree_v2.inner_nodes());

// Both trees share common nodes
assert!(store.num_internal_nodes() < tree_v1.inner_nodes().count() + tree_v2.inner_nodes().count());
```

### Efficient Proof Generation

Generate proofs from any stored tree:

```rust
let root_v1 = tree_v1.root();
let root_v2 = tree_v2.root();

// Get paths from either version
let path_v1 = store.get_path(root_v1, index).unwrap();
let path_v2 = store.get_path(root_v2, index).unwrap();
```

## Performance

- **Memory efficiency**: Common nodes are stored only once
- **Fast lookups**: O(log n) for node retrieval
- **Scalable**: Efficient for multiple tree versions

## Limitations

- **In-memory only**: All nodes must fit in memory
- **No persistence**: Store is not automatically persisted

## Related

- [MerkleTree](merkle-tree.md): Standard Merkle tree structure
- [SmtForest](smt-forest.md): Similar concept for Sparse Merkle Trees
- [Merkle Trees Overview](overview.md)

