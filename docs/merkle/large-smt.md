# LargeSmt

A large-scale Sparse Merkle Tree backed by pluggable storage, optimized for datasets that exceed available memory. Available when the `concurrent` feature is enabled.

## Overview

`LargeSmt` is designed for very large key-value sets that don't fit in memory. It uses a hybrid approach:

- **In-memory top**: Depths 0-23 are kept in memory for fast access
- **Storage-backed bottom**: Depths 24-64 are stored in external storage as fixed-size subtrees

## Key Features

- **Scalable**: Handles datasets exceeding RAM limits
- **Pluggable storage**: Supports in-memory and RocksDB backends
- **Batch operations**: Efficient batched updates
- **Persistent**: Can persist state to disk (with RocksDB)

## Construction

### With In-Memory Storage

```rust
use miden_crypto::merkle::smt::large::{LargeSmt, MemoryStorage};

let storage = MemoryStorage::new();
let mut smt = LargeSmt::new(storage);
```

### With RocksDB Storage

Requires the `rocksdb` feature:

```rust
use miden_crypto::merkle::smt::large::{LargeSmt, RocksDbStorage, RocksDbConfig};

let config = RocksDbConfig {
    path: "/path/to/db".into(),
    // ... other config
};

let storage = RocksDbStorage::new(config).unwrap();
let mut smt = LargeSmt::new(storage);
```

## Operations

### Insertion

```rust
let key = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
let value = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];

smt.insert(key, value).unwrap();
```

### Lookup

```rust
let value = smt.get(&key).unwrap();
```

### Batch Operations

```rust
use miden_crypto::merkle::smt::large::StorageUpdates;

let updates = StorageUpdates::new();
updates.insert(key1, value1);
updates.insert(key2, value2);

smt.apply_updates(updates).unwrap();
```

## Storage Backends

### MemoryStorage

In-memory storage for testing and smaller datasets:

```rust
use miden_crypto::merkle::smt::large::MemoryStorage;

let storage = MemoryStorage::new();
```

### RocksDbStorage

Persistent storage using RocksDB:

```rust
use miden_crypto::merkle::smt::large::{RocksDbStorage, RocksDbConfig};

let config = RocksDbConfig {
    path: "/path/to/db".into(),
    create_if_missing: true,
    // ... other options
};

let storage = RocksDbStorage::new(config).unwrap();
```

## Persistence

With RocksDB, the tree state is persisted to disk. On reopen:

```rust
// The in-memory top (depths 0-23) is reconstructed from persisted subtree roots
let storage = RocksDbStorage::new(config).unwrap();
let smt = LargeSmt::new(storage);
// Tree state is restored
```

## Performance Considerations

- **Memory usage**: Only top 24 levels in memory
- **Disk I/O**: Lower levels require disk access
- **Batch operations**: More efficient than individual operations

## Use Cases

### Large-Scale State

Store very large state trees:

```rust
let mut smt = LargeSmt::new(rocksdb_storage);

// Insert millions of entries
for (key, value) in large_dataset {
    smt.insert(key, value).unwrap();
}
```

### Persistent State

Maintain persistent state across restarts:

```rust
// Save state
smt.flush().unwrap();

// Later, reopen
let smt = LargeSmt::new(rocksdb_storage);
// State is restored
```

## Limitations

- **Requires `concurrent` feature**: Only available when `concurrent` is enabled
- **RocksDB dependency**: Requires `rocksdb` feature and clang for RocksDB backend
- **Performance**: Slower than in-memory SMT due to disk I/O

## Related

- [Smt](smt.md): In-memory SMT for smaller datasets
- [Merkle Trees Overview](overview.md)

