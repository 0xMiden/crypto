// Potential location: src/merkle/smt/storage.rs
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

use thiserror::Error;

use crate::merkle::smt::full::InnerNode; // Check path
use crate::merkle::smt::full::large::subtree::Subtree; // Check path (Used for deep nodes)
use crate::merkle::{NodeIndex, RpoDigest, SmtLeaf, smt::UnorderedMap};

#[cfg(feature = "rocksdb")]
mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksDbStorage;

mod memory;
pub use memory::MemoryStorage;

/// Custom error enum for storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Error originating from the underlying storage backend (e.g., RocksDB error).
    #[error("Storage backend error: {0}")]
    BackendError(String),
    /// Error during deserialization of data read from storage.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    /// Error during serialization of data before writing to storage.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Requested item was not found (optional, could also be handled by Option).
    #[error("Item not found in storage")]
    NotFound,
    /// An operation was attempted that is not supported by the storage implementation.
    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),
    /// Other storage-related errors.
    #[error("Storage error: {0}")]
    Other(String),
}

/// Structure holding a collection of updates to be applied atomically to storage.
#[derive(Default, Debug)]
pub struct StorageUpdates {
    /// Leaf updates: Map from logical leaf index (u64) to Option<SmtLeaf>.
    /// Some(leaf) means insert/update, None means delete.
    pub leaf_updates: UnorderedMap<u64, Option<SmtLeaf>>,

    /// Subtree updates (for deep nodes, depth > IN_MEMORY_DEPTH):
    /// Map from subtree root NodeIndex to Option<Subtree>.
    /// Some(subtree) means insert/update, None means delete.
    pub subtree_updates: UnorderedMap<NodeIndex, Option<Subtree>>,

    /// Upper node updates (for nodes with depth <= IN_MEMORY_DEPTH):
    /// Map from NodeIndex to Option<InnerNode>.
    /// Some(node) means insert/update, None means delete.
    pub upper_node_updates: UnorderedMap<NodeIndex, Option<InnerNode>>,

    /// The new root hash to be persisted atomically with the other updates.
    pub new_root: RpoDigest,

    /// Change in the total count of non-empty leaves for this batch.
    pub leaf_count_delta: isize,

    /// Change in the total count of key-value entries for this batch.
    pub entry_count_delta: isize,
}

pub trait SmtStorage: fmt::Debug + Send + Sync {
    /// Retrieves the stored root hash of the SMT. Returns Ok(None) if not set.
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError>;

    /// Sets the root hash of the SMT.
    fn set_root(&self, root: RpoDigest) -> Result<(), StorageError>;

    /// Gets the total number of non-empty leaves currently stored.
    fn get_leaf_count(&self) -> Result<usize, StorageError>;

    /// Gets the total number of key-value entries currently stored.
    fn get_entry_count(&self) -> Result<usize, StorageError>;

    /// Retrieves a single leaf node.
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError>;

    /// Sets a single leaf node.
    fn set_leaf(&self, index: u64, leaf: &SmtLeaf) -> Result<Option<SmtLeaf>, StorageError>;

    /// Sets multiple leaf nodes.
    fn set_leaves(&self, leaves: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError>;

    /// Removes a single leaf node.
    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError>;

    /// Retrieves multiple leaf nodes. Returns Ok(None) for indices not found.
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError>;

    /// Retrieves a single Subtree (representing deep nodes) by its root NodeIndex.
    /// Assumes index.depth() > IN_MEMORY_DEPTH. Returns Ok(None) if not found.
    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError>;

    /// Retrieves multiple Subtrees.
    /// Assumes index.depth() > IN_MEMORY_DEPTH for all indices. Returns Ok(None) for indices not
    /// found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError>;

    /// Sets a single Subtree (representing deep nodes) by its root NodeIndex.
    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError>;

    /// Sets multiple Subtrees (representing deep nodes) by their root NodeIndex.
    fn set_subtrees(&self, subtrees: Vec<Subtree>) -> Result<(), StorageError>;

    /// Removes a single Subtree (representing deep nodes) by its root NodeIndex.
    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError>;

    /// Retrieves a single inner node.
    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError>;

    /// Sets a single inner node.
    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError>;

    /// Removes a single inner node.
    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError>;

    /// Applies a set of updates atomically.
    /// This includes updates to leaves, deep subtrees, upper nodes, the root hash,
    /// and atomically updating persisted leaf/entry counts based on deltas.
    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError>;

    /// Returns an iterator over all leaves in the storage.
    /// The items are (leaf_index, SmtLeaf).
    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError>;

    /// Returns an iterator over all subtrees in the storage.
    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError>;

    /// Returns the Inner roots of all subtrees stored at the specified depth.
    fn get_subtree_roots_at_depth(&self, depth: u8) -> Result<Vec<(u64, RpoDigest)>, StorageError>;
}
