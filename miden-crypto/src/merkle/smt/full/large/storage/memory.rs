use alloc::{boxed::Box, string::ToString, vec::Vec};
use std::sync::RwLock;

use super::{SmtStorage, StorageError, StorageUpdates};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        EmptySubtreeRoots, InnerNode, NodeIndex, RpoDigest, SmtLeaf,
        smt::{
            UnorderedMap,
            full::large::{IN_MEMORY_DEPTH, SMT_DEPTH, subtree::Subtree},
        },
    },
};

/// In-memory storage for a Sparse Merkle Tree (SMT), implementing the `SmtStorage` trait.
///
/// This structure stores the SMT's root hash, leaf nodes, and subtrees directly in memory.
/// Access to these components is synchronized using `std::sync::RwLock` for thread safety.
///
/// It is primarily intended for scenarios where data persistence to disk is not a
/// primary concern. Common use cases include:
/// - Testing environments.
/// - Managing SMT instances with a limited operational lifecycle.
/// - Situations where a higher-level application architecture handles its own data persistence
///   strategy.
#[derive(Debug)]
pub struct MemoryStorage {
    pub root: RwLock<RpoDigest>,
    pub leaves: RwLock<UnorderedMap<u64, SmtLeaf>>,
    pub subtrees: RwLock<UnorderedMap<NodeIndex, Subtree>>,
}

impl MemoryStorage {
    /// Creates a new, empty in-memory storage for a Sparse Merkle Tree.
    ///
    /// Initializes the root to the empty SMT root for the defined SMT_DEPTH,
    /// and empty maps for leaves and subtrees.
    pub fn new() -> Self {
        let root_val = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        Self {
            root: RwLock::new(root_val),
            leaves: RwLock::new(UnorderedMap::new()),
            subtrees: RwLock::new(UnorderedMap::new()),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MemoryStorage {
    fn clone(&self) -> Self {
        MemoryStorage {
            root: RwLock::new(*self.root.read().expect("Failed to read lock for root in clone")),
            leaves: RwLock::new(
                self.leaves.read().expect("Failed to read lock for leaves in clone").clone(),
            ),
            subtrees: RwLock::new(
                self.subtrees.read().expect("Failed to read lock for subtrees in clone").clone(),
            ),
        }
    }
}

impl SmtStorage for MemoryStorage {
    /// Retrieves the current root hash of the Sparse Merkle Tree.
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError> {
        Ok(Some(*self.root.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for root".into())
        })?))
    }

    /// Sets the root hash of the Sparse Merkle Tree.
    fn set_root(&self, root: RpoDigest) -> Result<(), StorageError> {
        *self.root.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for root".into())
        })? = root;
        Ok(())
    }

    /// Gets the total number of non-empty leaves currently stored.
    fn leaf_count(&self) -> Result<usize, StorageError> {
        Ok(self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for leaves count".into())
            })?
            .len())
    }

    /// Gets the total number of key-value entries currently stored.
    fn entry_count(&self) -> Result<usize, StorageError> {
        Ok(self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for entry count".into())
            })?
            .iter()
            .map(|(_, leaf)| leaf.num_entries() as usize)
            .sum())
    }

    /// Inserts a key-value pair into the leaf at the given index.
    ///
    /// - If the leaf at `index` does not exist, a new `SmtLeaf::Single` is created.
    /// - If the leaf exists, the key-value pair is inserted into it.
    /// - Returns the previous value associated with the key, if any.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the write lock cannot be acquired.
    ///
    /// # Panics
    /// Panics in debug builds if `value` is `EMPTY_WORD`.
    fn insert_value(
        &self,
        index: u64,
        key: RpoDigest,
        value: Word,
    ) -> Result<Option<Word>, StorageError> {
        debug_assert_ne!(value, EMPTY_WORD);
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for insert_value".into())
        })?;

        match leaves_guard.get_mut(&index) {
            Some(leaf) => Ok(leaf.insert(key, value)),
            None => {
                leaves_guard.insert(index, SmtLeaf::Single((key, value)));
                Ok(None)
            },
        }
    }

    /// Removes a key-value pair from the leaf at the given `index`.
    ///
    /// - If the leaf at `index` exists and the `key` is found within that leaf, the key-value pair
    ///   is removed, and the old `Word` value is returned in `Ok(Some(Word))`.
    /// - If the leaf at `index` exists but the `key` is not found within that leaf, `Ok(None)` is
    ///   returned (as `leaf.get_value(&key)` would be `None`).
    /// - If the leaf at `index` does not exist, `Ok(None)` is returned, as no value could be
    ///   removed.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the write lock for leaves cannot be acquired.
    fn remove_value(&self, index: u64, key: RpoDigest) -> Result<Option<Word>, StorageError> {
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for remove_value".into())
        })?;

        match leaves_guard.get_mut(&index) {
            Some(leaf) => {
                let old_value = leaf.get_value(&key);
                leaf.remove(key);
                Ok(old_value)
            },
            None => {
                // Leaf at index does not exist, so no value could be removed.
                Ok(None)
            },
        }
    }

    /// Retrieves a single leaf node.
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        Ok(self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for get_leaf".into())
            })?
            .get(&index)
            .cloned())
    }

    /// Sets multiple leaf nodes in storage.
    ///
    /// If a leaf at a given index already exists, it is overwritten.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the write lock for leaves cannot be acquired.
    fn set_leaves(&self, leaves_map: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError> {
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for set_leaves".into())
        })?;
        leaves_guard.extend(leaves_map);
        Ok(())
    }

    /// Removes a single leaf node.
    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        Ok(self
            .leaves
            .write()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire write lock for remove_leaf".into())
            })?
            .remove(&index))
    }

    /// Retrieves multiple leaf nodes. Returns Ok(None) for indices not found.
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let leaves_guard = self.leaves.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for get_leaves".into())
        })?;
        let leaves = indices.iter().map(|idx| leaves_guard.get(idx).cloned()).collect();
        Ok(leaves)
    }

    /// Returns true if the storage has any leaves.
    fn has_leaves(&self) -> Result<bool, StorageError> {
        let leaves_guard = self.leaves.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for get_leaves".into())
        })?;
        Ok(!leaves_guard.is_empty())
    }

    /// Retrieves a single Subtree (representing deep nodes) by its root NodeIndex.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH. Returns Ok(None) if not found.
    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        Ok(self
            .subtrees
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for get_subtree".into())
            })?
            .get(&index)
            .cloned())
    }

    /// Retrieves multiple Subtrees.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH for all indices. Returns Ok(None) for indices not
    /// found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for get_subtrees".into())
        })?;
        let subtrees: Vec<_> = indices.iter().map(|idx| subtrees_guard.get(idx).cloned()).collect();
        Ok(subtrees)
    }

    /// Sets a single Subtree (representing deep nodes) by its root NodeIndex.
    ///
    /// If a subtree with the same root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH`.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the write lock for subtrees cannot be acquired.
    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError> {
        self.subtrees
            .write()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire write lock for set_subtree".into())
            })?
            .insert(subtree.root_index(), subtree.clone());
        Ok(())
    }

    /// Sets multiple Subtrees (representing deep nodes) by their root NodeIndex.
    ///
    /// If a subtree with a given root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH` for all subtrees in the vector.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the write lock for subtrees cannot be acquired.
    fn set_subtrees(&self, subtrees_vec: Vec<Subtree>) -> Result<(), StorageError> {
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for set_subtrees".into())
        })?;
        subtrees_guard
            .extend(subtrees_vec.into_iter().map(|subtree| (subtree.root_index(), subtree)));
        Ok(())
    }

    /// Removes a single Subtree (representing deep nodes) by its root NodeIndex.
    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError> {
        self.subtrees
            .write()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire write lock for remove_subtree".into())
            })?
            .remove(&index);
        Ok(())
    }

    /// Retrieves a single inner node from a Subtree.
    ///
    /// This function is intended for accessing nodes within a Subtree, meaning
    /// `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    ///
    /// # Errors
    /// - `StorageError::BackendError`: If `index.depth() < IN_MEMORY_DEPTH`.
    /// - `StorageError::BackendError`: If the read lock for subtrees cannot be acquired.
    ///
    /// Returns `Ok(None)` if the subtree or the specific inner node within it is not found.
    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::BackendError(
                "Cannot get inner node from upper part of the tree".to_string(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire read lock for get_inner_node (subtrees)".into(),
            )
        })?;
        Ok(subtrees_guard
            .get(&subtree_root_index)
            .and_then(|subtree| subtree.get_inner_node(index)))
    }

    /// Sets a single inner node within a Subtree.
    ///
    /// - `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    /// - If the target Subtree does not exist, it is created.
    /// - The `node` is then inserted into the Subtree.
    ///
    /// Returns the `InnerNode` that was previously at this `index`, if any.
    ///
    /// # Errors
    /// - `StorageError::BackendError`: If `index.depth() < IN_MEMORY_DEPTH`.
    /// - `StorageError::BackendError`: If the write lock for subtrees cannot be acquired.
    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::BackendError(
                "Cannot set inner node in upper part of the tree".to_string(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire write lock for set_inner_node (subtrees)".into(),
            )
        })?;
        let mut subtree = subtrees_guard
            .remove(&subtree_root_index)
            .unwrap_or_else(|| Subtree::new(subtree_root_index));
        let old_node = subtree.insert_inner_node(index, node);
        subtrees_guard.insert(subtree_root_index, subtree);
        Ok(old_node)
    }

    /// Removes a single inner node from a Subtree.
    ///
    /// - `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    /// - If the Subtree becomes empty after removing the node, the Subtree itself is removed from
    ///   storage.
    ///
    /// Returns the `InnerNode` that was removed, if any.
    ///
    /// # Errors
    /// - `StorageError::BackendError`: If `index.depth() < IN_MEMORY_DEPTH`.
    /// - `StorageError::BackendError`: If the write lock for subtrees cannot be acquired.
    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::BackendError(
                "Cannot remove inner node from upper part of the tree".to_string(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire write lock for remove_inner_node (subtrees)".into(),
            )
        })?;

        let inner_node: Option<InnerNode> =
            subtrees_guard.remove(&subtree_root_index).and_then(|mut subtree| {
                let old_node = subtree.remove_inner_node(index);
                if !subtree.is_empty() {
                    subtrees_guard.insert(subtree_root_index, subtree);
                }
                old_node
            });
        Ok(inner_node)
    }

    /// Applies a set of updates atomically to the storage.
    ///
    /// This method handles updates to:
    /// - Leaves: Inserts new or updated leaves, removes specified leaves.
    /// - Subtrees: Inserts new or updated subtrees, removes specified subtrees.
    /// - Root hash: Sets the new root hash of the SMT.
    ///
    /// All operations are performed after acquiring write locks on the root, leaves, and subtrees
    /// collections, ensuring atomicity of the batch update.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if any of the necessary write locks
    /// (for root, leaves, or subtrees) cannot be acquired.
    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError> {
        let mut root_guard = self.root.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for root in apply".into())
        })?;
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for leaves in apply".into())
        })?;
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for subtrees in apply".into())
        })?;

        let (leaf_updates, subtree_updates, new_root, _leaf_count_delta, _entry_count_delta) =
            updates.into_parts();

        for (index, leaf_opt) in leaf_updates {
            if let Some(leaf) = leaf_opt {
                leaves_guard.insert(index, leaf);
            } else {
                leaves_guard.remove(&index);
            }
        }
        for (index, subtree_opt) in subtree_updates {
            if let Some(subtree) = subtree_opt {
                subtrees_guard.insert(index, subtree);
            } else {
                subtrees_guard.remove(&index);
            }
        }
        *root_guard = new_root;
        Ok(())
    }

    /// Returns an iterator over all (index, SmtLeaf) pairs in the storage.
    ///
    /// The iterator provides access to the current state of the leaves.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the read lock for leaves cannot be acquired.
    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        let leaves_guard = self.leaves.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for iter_leaves".into())
        })?;
        let leaves_vec = leaves_guard.iter().map(|(&k, v)| (k, v.clone())).collect::<Vec<_>>();
        Ok(Box::new(leaves_vec.into_iter()))
    }

    /// Returns an iterator over all Subtrees in the storage.
    ///
    /// The iterator provides access to the current subtrees from storage.
    ///
    /// # Errors
    /// Returns `StorageError::BackendError` if the read lock for subtrees cannot be acquired.
    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for iter_subtrees".into())
        })?;
        let subtrees_vec = subtrees_guard.values().cloned().collect::<Vec<_>>();
        Ok(Box::new(subtrees_vec.into_iter()))
    }

    /// Retrieves all depth 24 roots for fast tree rebuilding.
    ///
    /// For MemoryStorage, this returns an empty vector since all data is already in memory
    /// and there's no startup performance benefit to caching depth 24 roots.
    fn get_depth24(&self) -> Result<Vec<(u64, RpoDigest)>, StorageError> {
        Ok(Vec::new())
    }
}
