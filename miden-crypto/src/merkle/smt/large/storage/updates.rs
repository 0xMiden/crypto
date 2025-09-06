use crate::{
    Word,
    merkle::{
        NodeIndex, SmtLeaf,
        smt::{Map, large::subtree::Subtree},
    },
};

/// Owned decomposition of a [`StorageUpdates`] batch into its constituent parts.
///
/// This struct provides direct access to the individual components of a storage update
/// batch after transferring ownership from [`StorageUpdates::into_parts`].
#[derive(Debug)]
pub struct StorageUpdateParts {
    /// Leaf updates indexed by their position in the tree.
    ///
    /// `Some(leaf)` indicates an insertion or update, while `None` indicates deletion.
    pub leaf_updates: Map<u64, Option<SmtLeaf>>,

    /// Subtree updates indexed by their root node position.
    ///
    /// `Some(subtree)` indicates an insertion or update, while `None` indicates deletion.
    pub subtree_updates: Map<NodeIndex, Option<Subtree>>,

    /// Root hash of the tree after applying all updates.
    pub new_root: Word,

    /// Net change in the count of non-empty leaves.
    ///
    /// Positive values indicate more leaves were added than removed,
    /// negative values indicate more leaves were removed than added.
    pub leaf_count_delta: isize,

    /// Net change in the total number of key-value entries across all leaves.
    ///
    /// Positive values indicate more entries were added than removed,
    /// negative values indicate more entries were removed than added.
    pub entry_count_delta: isize,
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
    leaf_updates: Map<u64, Option<SmtLeaf>>,

    /// A map of updates to SMT subtrees.
    /// The key is the `NodeIndex` of the subtree's root.
    /// - `Some(Subtree)` indicates an insertion or update of the subtree.
    /// - `None` indicates a deletion of the subtree.
    subtree_updates: Map<NodeIndex, Option<Subtree>>,

    /// The new root hash of the SMT that should be persisted after applying
    /// all `leaf_updates` and `subtree_updates`.
    new_root: Word,

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
    pub fn new(new_root: Word) -> Self {
        Self { new_root, ..Default::default() }
    }

    /// Creates a new `StorageUpdates` from pre-computed components.
    ///
    /// This constructor is ideal for bulk operations where you already have
    /// the complete maps of updates and calculated deltas, such as when applying
    /// a batch of mutations.
    pub fn from_parts(
        leaf_updates: Map<u64, Option<SmtLeaf>>,
        subtree_updates: Map<NodeIndex, Option<Subtree>>,
        new_root: Word,
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
    pub fn leaf_updates(&self) -> &Map<u64, Option<SmtLeaf>> {
        &self.leaf_updates
    }

    /// Returns a reference to the subtree updates map.
    pub fn subtree_updates(&self) -> &Map<NodeIndex, Option<Subtree>> {
        &self.subtree_updates
    }

    /// Returns the new root hash.
    pub fn new_root(&self) -> Word {
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
    pub fn into_leaf_updates(self) -> Map<u64, Option<SmtLeaf>> {
        self.leaf_updates
    }

    /// Consumes this StorageUpdates and returns the subtree updates map.
    pub fn into_subtree_updates(self) -> Map<NodeIndex, Option<Subtree>> {
        self.subtree_updates
    }

    /// Consumes this `StorageUpdates` and returns its owned parts as a [`StorageUpdateParts`].
    pub fn into_parts(self) -> StorageUpdateParts {
        StorageUpdateParts {
            leaf_updates: self.leaf_updates,
            subtree_updates: self.subtree_updates,
            new_root: self.new_root,
            leaf_count_delta: self.leaf_count_delta,
            entry_count_delta: self.entry_count_delta,
        }
    }
}
