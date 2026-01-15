# Merkle Trees Overview

Miden Crypto provides a comprehensive set of Merkle tree data structures, all implemented using the RPO256 hash function. These structures are essential for creating efficient commitments and proofs in zero-knowledge systems.

## Available Data Structures

### Standard Merkle Trees

- **[MerkleTree](merkle-tree.md)**: A fully-balanced binary Merkle tree with power-of-two leaves
- **[MerkleStore](merkle-store.md)**: A collection of Merkle trees designed to efficiently store trees with common subtrees

### Merkle Mountain Ranges

- **[MMR](mmr.md)**: Merkle Mountain Range structure designed to function as an append-only log
- **[PartialMmr](mmr.md#partial-mmr)**: A partial view of a Merkle Mountain Range

### Partial Trees

- **[PartialMerkleTree](partial-mt.md)**: A partial view of a Merkle tree where some sub-trees may not be known

### Sparse Merkle Trees

- **[SimpleSmt](smt.md#simple-smt)**: A Sparse Merkle Tree with no compaction, mapping 64-bit keys to 4-element values
- **[Smt](smt.md)**: A Sparse Merkle Tree with compaction at depth 64, mapping 4-element keys to 4-element values
- **[LargeSmt](large-smt.md)**: A large-scale Sparse Merkle Tree backed by pluggable storage (e.g., RocksDB)
- **[SmtForest](smt-forest.md)**: A collection of Sparse Merkle Trees with depth 64, designed to efficiently store trees with common subtrees

## Common Operations

All Merkle tree structures support similar operations:

### Getting the Root

```rust
use miden_crypto::merkle::MerkleTree;

let tree = MerkleTree::new(leaves).unwrap();
let root = tree.root();
```

### Getting a Path/Proof

```rust
use miden_crypto::merkle::{MerkleTree, NodeIndex};

let tree = MerkleTree::new(leaves).unwrap();
let index = NodeIndex::new(depth, leaf_index).unwrap();
let path = tree.get_path(index).unwrap();
```

### Verifying a Proof

```rust
use miden_crypto::merkle::MerkleProof;

let proof = MerkleProof::new(leaf, path);
let is_valid = proof.verify(root, index);
```

## Choosing a Data Structure

### Use MerkleTree when:
- You have a fixed set of leaves (power of two)
- You need a simple, standard Merkle tree
- All leaves are known at construction time

### Use MerkleStore when:
- You need to store multiple trees with common subtrees
- You want to efficiently manage multiple tree versions
- Memory efficiency is important

### Use MMR when:
- You need an append-only log structure
- You want to efficiently prove membership in a growing set
- You need to prove consistency between different states

### Use PartialMerkleTree when:
- You only have partial knowledge of the tree
- You're working with Merkle paths from different sources
- You need to combine proofs from different trees

### Use SimpleSmt when:
- You need a simple key-value store with 64-bit keys
- You don't need compaction
- You have a small to medium number of entries

### Use Smt when:
- You need a key-value store with 4-element keys
- You want compaction for efficiency
- You have a medium number of entries

### Use LargeSmt when:
- You have a very large number of entries (exceeding memory)
- You need persistent storage (RocksDB)
- You need to scale beyond RAM limits

### Use SmtForest when:
- You need multiple SMTs with common subtrees
- You want to efficiently manage multiple tree versions
- You need to prune old unused trees

## Hash Function

All Merkle tree structures use **RPO256** as the underlying hash function. This ensures:

- Consistency across all tree types
- Efficient verification in STARKs
- Standardized security properties

## Next Steps

- [MerkleTree](merkle-tree.md): Learn about standard Merkle trees
- [MerkleStore](merkle-store.md): Learn about efficient tree storage
- [MMR](mmr.md): Learn about Merkle Mountain Ranges
- [SMT](smt.md): Learn about Sparse Merkle Trees
- [LargeSmt](large-smt.md): Learn about large-scale SMTs

