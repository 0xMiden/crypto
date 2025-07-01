use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

use thiserror::Error;

use crate::{
    Word,
    merkle::{
        NodeIndex, RpoDigest, SmtLeaf,
        smt::{
            UnorderedMap,
            full::{InnerNode, large::subtree::Subtree},
        },
    },
};

#[cfg(feature = "rocksdb")]
mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::{RocksDbConfig, RocksDbStorage};

mod memory;
pub use memory::MemoryStorage;

/// Defines the set of errors that can occur during SMT storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// An error originating from the underlying storage backend (e.g., a database error).
    #[error("Storage backend error: {0}")]
    BackendError(String),
    /// Error during deserialization of data read from storage.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    /// Error during serialization of data before writing to storage.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Indicates that a requested item was not found in the storage.
    #[error("Item not found in storage")]
    NotFound,
    /// An operation was attempted that is not supported by the current storage implementation.
    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),
    /// A catch-all for other storage-related errors not covered by more specific variants.
    /// Contains a string describing the error.
    #[error("Storage error: {0}")]
    Other(String),
}

/// Represents a collection of changes to be applied atomically to an SMT storage backend.
///
/// This struct is used to batch multiple updates (to leaves, subtrees, and the SMT root)
/// ensuring that they are persisted together as a single, consistent transaction.
/// It also tracks deltas for leaf and entry counts, allowing storage implementations
/// to maintain these counts accurately.
#[derive(Default, Debug, Clone)]
pub struct StorageUpdates {
    /// A map of updates to individual SMT leaves.
    /// The key is the logical leaf index (u64).
    /// - `Some(SmtLeaf)` indicates an insertion or update of the leaf at that index.
    /// - `None` indicates a deletion of the leaf at that index.
    leaf_updates: UnorderedMap<u64, Option<SmtLeaf>>,

    /// A map of updates to SMT subtrees.
    /// The key is the `NodeIndex` of the subtree's root.
    /// - `Some(Subtree)` indicates an insertion or update of the subtree.
    /// - `None` indicates a deletion of the subtree.
    subtree_updates: UnorderedMap<NodeIndex, Option<Subtree>>,

    /// The new root hash of the SMT that should be persisted after applying
    /// all `leaf_updates` and `subtree_updates`.
    new_root: RpoDigest,

    /// The net change in the total count of non-empty leaves resulting from this batch of updates.
    /// For example, if one leaf is added and one is removed, this would be 0.
    /// If two new leaves are added, this would be +2.
    leaf_count_delta: isize,

    /// The net change in the total count of key-value entries across all leaves
    /// resulting from this batch of updates.
    entry_count_delta: isize,
}

impl StorageUpdates {
    /// Creates a new `StorageUpdates` with the specified root hash and default empty updates.
    ///
    /// This constructor is ideal for incremental building where you'll add updates
    /// one by one using the convenience methods like `insert_leaf()` and `insert_subtree()`.
    pub fn new(new_root: RpoDigest) -> Self {
        Self { new_root, ..Default::default() }
    }

    /// Creates a new `StorageUpdates` from pre-computed components.
    ///
    /// This constructor is ideal for bulk operations where you already have
    /// the complete maps of updates and calculated deltas, such as when applying
    /// a batch of mutations.
    pub fn from_parts(
        leaf_updates: UnorderedMap<u64, Option<SmtLeaf>>,
        subtree_updates: UnorderedMap<NodeIndex, Option<Subtree>>,
        new_root: RpoDigest,
        leaf_count_delta: isize,
        entry_count_delta: isize,
    ) -> Self {
        Self {
            leaf_updates,
            subtree_updates,
            new_root,
            leaf_count_delta,
            entry_count_delta,
        }
    }

    /// Adds a leaf insertion/update to the batch.
    pub fn insert_leaf(&mut self, index: u64, leaf: SmtLeaf) {
        self.leaf_updates.insert(index, Some(leaf));
    }

    /// Adds a leaf removal to the batch.
    pub fn remove_leaf(&mut self, index: u64) {
        self.leaf_updates.insert(index, None);
    }

    /// Adds a subtree insertion/update to the batch.
    pub fn insert_subtree(&mut self, subtree: Subtree) {
        let index = subtree.root_index();
        self.subtree_updates.insert(index, Some(subtree));
    }

    /// Adds a subtree removal to the batch.
    pub fn remove_subtree(&mut self, index: NodeIndex) {
        self.subtree_updates.insert(index, None);
    }

    /// Returns true if this update batch contains no changes.
    pub fn is_empty(&self) -> bool {
        self.leaf_updates.is_empty() && self.subtree_updates.is_empty()
    }

    /// Returns the number of leaf updates in this batch.
    pub fn leaf_update_count(&self) -> usize {
        self.leaf_updates.len()
    }

    /// Returns the number of subtree updates in this batch.
    pub fn subtree_update_count(&self) -> usize {
        self.subtree_updates.len()
    }

    /// Returns a reference to the leaf updates map.
    pub fn leaf_updates(&self) -> &UnorderedMap<u64, Option<SmtLeaf>> {
        &self.leaf_updates
    }

    /// Returns a reference to the subtree updates map.
    pub fn subtree_updates(&self) -> &UnorderedMap<NodeIndex, Option<Subtree>> {
        &self.subtree_updates
    }

    /// Returns the new root hash.
    pub fn new_root(&self) -> RpoDigest {
        self.new_root
    }

    /// Returns the leaf count delta.
    pub fn leaf_count_delta(&self) -> isize {
        self.leaf_count_delta
    }

    /// Returns the entry count delta.
    pub fn entry_count_delta(&self) -> isize {
        self.entry_count_delta
    }

    /// Sets the leaf count delta.
    pub fn set_leaf_count_delta(&mut self, delta: isize) {
        self.leaf_count_delta = delta;
    }

    /// Sets the entry count delta.
    pub fn set_entry_count_delta(&mut self, delta: isize) {
        self.entry_count_delta = delta;
    }

    /// Adjusts the leaf count delta by the specified amount.
    pub fn adjust_leaf_count_delta(&mut self, adjustment: isize) {
        self.leaf_count_delta += adjustment;
    }

    /// Adjusts the entry count delta by the specified amount.
    pub fn adjust_entry_count_delta(&mut self, adjustment: isize) {
        self.entry_count_delta += adjustment;
    }

    /// Consumes this StorageUpdates and returns the leaf updates map.
    pub fn into_leaf_updates(self) -> UnorderedMap<u64, Option<SmtLeaf>> {
        self.leaf_updates
    }

    /// Consumes this StorageUpdates and returns the subtree updates map.
    pub fn into_subtree_updates(self) -> UnorderedMap<NodeIndex, Option<Subtree>> {
        self.subtree_updates
    }

    /// Consumes this StorageUpdates and returns all components.
    ///
    /// First component is the leaf updates map.
    /// Second component is the subtree updates map.
    /// Third component is the new root hash.
    /// Fourth component is the leaf count delta.
    /// Fifth component is the entry count delta.
    pub fn into_parts(
        self,
    ) -> (
        UnorderedMap<u64, Option<SmtLeaf>>,
        UnorderedMap<NodeIndex, Option<Subtree>>,
        RpoDigest,
        isize,
        isize,
    ) {
        (
            self.leaf_updates,
            self.subtree_updates,
            self.new_root,
            self.leaf_count_delta,
            self.entry_count_delta,
        )
    }
}

/// Sparse Merkle Tree storage backend.
///
/// This trait outlines the fundamental operations required to persist and retrieve
/// the components of an SMT, such as its root hash, leaves, and deeper subtrees.
/// Implementations of this trait can provide various storage solutions, like in-memory
/// maps or persistent databases (e.g., RocksDB).
///
/// All methods are expected to handle potential storage errors by returning a
/// `Result<_, StorageError>`.
pub trait SmtStorage: 'static + fmt::Debug + Send + Sync {
    /// Retrieves the current root hash of the Sparse Merkle Tree.
    /// Returns `Ok(None)` if no root has been set or an empty SMT is represented.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError>;

    /// Sets or updates the root hash of the Sparse Merkle Tree.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage write operation fails.
    fn set_root(&self, root: RpoDigest) -> Result<(), StorageError>;

    /// Retrieves the total number of leaf nodes currently stored.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn leaf_count(&self) -> Result<usize, StorageError>;

    /// Retrieves the total number of unique key-value entries across all leaf nodes.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn entry_count(&self) -> Result<usize, StorageError>;

    /// Inserts a key-value pair into the SMT leaf at the specified logical `index`.
    ///
    /// - If the leaf at `index` does not exist, it may be created.
    /// - If the `key` already exists in the leaf at `index`, its `value` is updated.
    /// - Returns the previous `Word` value associated with the `key` at `index`, if any.
    ///
    /// Implementations are responsible for updating overall leaf and entry counts if necessary.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage operation fails (e.g., backend database error,
    /// insufficient space, serialization failures).
    fn insert_value(
        &self,
        index: u64,
        key: RpoDigest,
        value: Word,
    ) -> Result<Option<Word>, StorageError>;

    /// Removes a key-value pair from the SMT leaf at the specified logical `index`.
    ///
    /// - If the `key` is found in the leaf at `index`, it is removed, and the old `Word` value is
    ///   returned.
    /// - If the leaf at `index` does not exist, or if the `key` is not found within it, `Ok(None)`
    ///   is returned.
    /// - If removing the entry causes the leaf to become empty, the behavior regarding the leaf
    ///   node itself (e.g., whether it's removed from storage) is implementation-dependent, but
    ///   counts should be updated.
    ///
    /// Implementations are responsible for updating overall leaf and entry counts if necessary.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage operation fails (e.g., backend database error,
    /// write permission issues, serialization failures).
    fn remove_value(&self, index: u64, key: RpoDigest) -> Result<Option<Word>, StorageError>;

    /// Retrieves a single SMT leaf node by its logical `index`.
    /// Returns `Ok(None)` if no leaf exists at the given `index`.
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError>;

    /// Sets or updates multiple SMT leaf nodes in storage.
    ///
    /// For each entry in the `leaves` map, if a leaf at the given index already exists,
    /// it should be overwritten with the new `SmtLeaf` data.
    /// If it does not exist, a new leaf is stored.
    ///
    /// # Errors
    /// Returns `StorageError` if any storage operation fails during the batch update.
    fn set_leaves(&self, leaves: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError>;

    /// Removes a single SMT leaf node entirely from storage by its logical `index`.
    ///
    /// Returns the `SmtLeaf` that was removed, or `Ok(None)` if no leaf existed at `index`.
    /// Implementations should ensure that removing a leaf also correctly updates
    /// the overall leaf and entry counts.
    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError>;

    /// Retrieves multiple SMT leaf nodes by their logical `indices`.
    ///
    /// The returned `Vec` will have the same length as the input `indices` slice.
    /// For each `index` in the input, the corresponding element in the output `Vec`
    /// will be `Some(SmtLeaf)` if found, or `None` if not found.
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError>;

    /// Returns true if the storage has any leaves.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn has_leaves(&self) -> Result<bool, StorageError>;

    /// Retrieves a single SMT Subtree by its root `NodeIndex`.
    ///
    /// Subtrees typically represent deeper, compacted parts of the SMT.
    /// Returns `Ok(None)` if no subtree is found for the given `index`.
    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError>;

    /// Retrieves multiple Subtrees by their root `NodeIndex` values.
    ///
    /// The returned `Vec` will have the same length as the input `indices` slice.
    /// For each `index` in the input, the corresponding element in the output `Vec`
    /// will be `Some(Subtree)` if found, or `None` if not found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError>;

    /// Sets or updates a single SMT Subtree in storage, identified by its root `NodeIndex`.
    ///
    /// If a subtree with the same root `NodeIndex` already exists, it is overwritten.
    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError>;

    /// Sets or updates multiple SMT Subtrees in storage.
    ///
    /// For each `Subtree` in the `subtrees` vector, if a subtree with the same root `NodeIndex`
    /// already exists, it is overwritten.
    fn set_subtrees(&self, subtrees: Vec<Subtree>) -> Result<(), StorageError>;

    /// Removes a single SMT Subtree from storage, identified by its root `NodeIndex`.
    ///
    /// Returns `Ok(())` on successful removal or if the subtree did not exist.
    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError>;

    /// Retrieves a single inner node from within a Subtree.
    ///
    /// This method is intended for accessing nodes at depths greater than the in-memory horizon.
    /// Returns `Ok(None)` if the containing Subtree or the specific inner node is not found.
    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError>;

    /// Sets or updates a single inner node (non-leaf node) within a Subtree.
    ///
    /// - If the target Subtree does not exist, it might need to be created by the implementation.
    /// - Returns the `InnerNode` that was previously at this `index`, if any.
    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError>;

    /// Removes a single inner node (non-leaf node) from within a Subtree.
    ///
    /// - If the Subtree becomes empty after removing the node, the Subtree itself might be removed
    ///   by the storage implementation.
    /// - Returns the `InnerNode` that was removed, if any.
    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError>;

    /// Applies a batch of `StorageUpdates` atomically to the storage backend.
    ///
    /// This is the primary method for persisting changes to the SMT. Implementations must ensure
    /// that all updates within the `StorageUpdates` struct (leaf changes, subtree changes,
    /// new root hash, and count deltas) are applied as a single, indivisible operation.
    /// If any part of the update fails, the entire transaction should be rolled back, leaving
    /// the storage in its previous state.
    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError>;

    /// Returns an iterator over all (logical_index, SmtLeaf) pairs currently in storage.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError>;

    /// Returns an iterator over all `Subtree` instances currently in storage.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError>;

    /// Retrieves all depth 24 hashes from storage for efficient startup reconstruction.
    ///
    /// Returns a vector of `(node_index_value, InnerNode)` tuples representing
    /// the cached roots of nodes at depth 24 (the in-memory/storage boundary).
    /// These roots enable fast reconstruction of the upper tree without loading
    /// entire subtrees.
    ///
    /// The hash cache is automatically maintained by subtree operations - no manual
    /// cache management is required.
    fn get_depth24(&self) -> Result<Vec<(u64, RpoDigest)>, StorageError>;
}
