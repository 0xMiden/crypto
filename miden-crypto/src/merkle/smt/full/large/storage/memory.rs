use alloc::{boxed::Box, string::ToString, vec::Vec};
use std::sync::RwLock;

use super::{SmtStorage, StorageError, StorageUpdates};
use crate::merkle::{
    EmptySubtreeRoots, InnerNode, NodeIndex, RpoDigest, SmtLeaf,
    smt::{
        UnorderedMap,
        full::large::{IN_MEMORY_DEPTH, SMT_DEPTH, subtree::Subtree},
    },
};

#[derive(Debug)]
pub struct MemoryStorage {
    pub root: RwLock<RpoDigest>,
    pub leaves: RwLock<UnorderedMap<u64, SmtLeaf>>,
    pub subtrees: RwLock<UnorderedMap<NodeIndex, Subtree>>,
}

impl MemoryStorage {
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
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError> {
        Ok(Some(*self.root.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for root".into())
        })?))
    }

    fn set_root(&self, root: RpoDigest) -> Result<(), StorageError> {
        *self.root.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for root".into())
        })? = root;
        Ok(())
    }

    /// Gets the total number of non-empty leaves currently stored.
    fn get_leaf_count(&self) -> Result<usize, StorageError> {
        Ok(self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for leaves count".into())
            })?
            .len())
    }

    /// Gets the total number of key-value entries currently stored.
    fn get_entry_count(&self) -> Result<usize, StorageError> {
        Ok(self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for entry count".into())
            })?
            .len())
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

    /// Sets a single leaf node.
    fn set_leaf(&self, index: u64, leaf: &SmtLeaf) -> Result<Option<SmtLeaf>, StorageError> {
        Ok(self
            .leaves
            .write()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire write lock for set_leaf".into())
            })?
            .insert(index, leaf.clone()))
    }

    /// Sets multiple leaf nodes.
    fn set_leaves(&self, leaves_map: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError> {
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for set_leaves".into())
        })?;
        for (index, leaf) in leaves_map {
            leaves_guard.insert(index, leaf);
        }
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
        let mut res = Vec::with_capacity(indices.len());
        for &idx in indices {
            res.push(leaves_guard.get(&idx).cloned());
        }
        Ok(res)
    }

    /// Retrieves a single Subtree (representing deep nodes) by its root NodeIndex.
    /// Assumes index.depth() > IN_MEMORY_DEPTH. Returns Ok(None) if not found.
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
    /// Assumes index.depth() > IN_MEMORY_DEPTH for all indices. Returns Ok(None) for indices not
    /// found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for get_subtrees".into())
        })?;
        let mut res = Vec::with_capacity(indices.len());
        for &idx in indices {
            res.push(subtrees_guard.get(&idx).cloned());
        }
        Ok(res)
    }

    /// Sets a single Subtree (representing deep nodes) by its root NodeIndex.
    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError> {
        self.subtrees
            .write()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire write lock for set_subtree".into())
            })?
            .insert(subtree.root_index, subtree.clone());
        Ok(())
    }

    /// Sets multiple Subtrees (representing deep nodes) by their root NodeIndex.
    fn set_subtrees(&self, subtrees_vec: Vec<Subtree>) -> Result<(), StorageError> {
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError("Failed to acquire write lock for set_subtrees".into())
        })?;
        for subtree in subtrees_vec {
            subtrees_guard.insert(subtree.root_index, subtree);
        }
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

    /// Retrieves a single inner node.
    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
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
        match subtrees_guard.get(&subtree_root_index) {
            Some(subtree) => Ok(subtree.get_inner_node(index)),
            None => Ok(None),
        }
    }

    /// Sets a single inner node.
    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            Err(StorageError::BackendError(
                "Cannot set inner node in upper part of the tree".to_string(),
            ))
        } else {
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
    }

    /// Removes a single inner node.
    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
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
        if let Some(mut subtree) = subtrees_guard.remove(&subtree_root_index) {
            let old_node = subtree.remove_inner_node(index);
            if !subtree.is_empty() {
                subtrees_guard.insert(subtree_root_index, subtree);
            }
            Ok(old_node)
        } else {
            Ok(None)
        }
    }

    /// Applies a set of updates atomically.
    /// This includes updates to leaves, deep subtrees, upper nodes, the root hash,
    /// and atomically updating persisted leaf/entry counts based on deltas.
    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError> {
        let mut root_guard = self.root.write().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire write lock for root in apply_batch".into(),
            )
        })?;
        let mut leaves_guard = self.leaves.write().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire write lock for leaves in apply_batch".into(),
            )
        })?;
        let mut subtrees_guard = self.subtrees.write().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire write lock for subtrees in apply_batch".into(),
            )
        })?;

        for (index, leaf_opt) in updates.leaf_updates {
            match leaf_opt {
                Some(leaf) => {
                    leaves_guard.insert(index, leaf);
                },
                None => {
                    leaves_guard.remove(&index);
                },
            };
        }
        for (index, subtree_opt) in updates.subtree_updates {
            match subtree_opt {
                Some(subtree) => {
                    subtrees_guard.insert(index, subtree);
                },
                None => {
                    subtrees_guard.remove(&index);
                },
            };
        }
        *root_guard = updates.new_root;
        Ok(())
    }

    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        let leaves_iter = self
            .leaves
            .read()
            .map_err(|_| {
                StorageError::BackendError("Failed to acquire read lock for iter_leaves".into())
            })?
            .clone()
            .into_iter();
        Ok(Box::new(leaves_iter))
    }

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError("Failed to acquire read lock for iter_subtrees".into())
        })?;
        let subtrees_iter = subtrees_guard.values().cloned().collect::<Vec<_>>().into_iter();
        Ok(Box::new(subtrees_iter))
    }

    fn get_subtree_roots_at_depth(&self, depth: u8) -> Result<Vec<(u64, RpoDigest)>, StorageError> {
        let mut roots = Vec::new();
        let subtrees_guard = self.subtrees.read().map_err(|_| {
            StorageError::BackendError(
                "Failed to acquire read lock for get_subtree_roots_at_depth".into(),
            )
        })?;

        for (index, subtree) in subtrees_guard.iter() {
            if index.depth() == depth {
                match subtree.get_inner_node(*index) {
                    Some(inner_node) => {
                        roots.push((index.value(), inner_node.hash()));
                    },
                    None => {
                        return Err(StorageError::Other(format!(
                            "Root node {index} not found in its own in-memory subtree during get_subtree_roots_at_depth",
                        )));
                    },
                }
            }
        }
        Ok(roots)
    }
}
