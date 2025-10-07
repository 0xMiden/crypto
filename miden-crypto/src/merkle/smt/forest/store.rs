use alloc::vec::Vec;

use crate::{
    Map, Word,
    hash::rpo::Rpo256,
    merkle::{EmptySubtreeRoots, MerkleError, MerklePath, MerkleProof, NodeIndex, SMT_DEPTH},
};

// SMT FOREST STORE
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct SmtNode {
    left: Word,
    right: Word,
    rc: usize,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub(super) struct SmtStore {
    nodes: Map<Word, SmtNode>,
}

/// An in-memory data store for SmtForest data.
///
/// This is an internal memory data store for SmtForest data. Similarly to the `MerkleStore`, it
/// allows all the nodes of multiple trees to live as long as necessary and without duplication,
/// this allows the implementation of space efficient persistent data structures.
///
/// Unlike `MerkleStore`, unused nodes can be easily removed from the store by leveraing
/// reference counting.
impl SmtStore {
    /// Creates a new, empty in-memory store for SmtForest data.
    pub fn new() -> Self {
        // pre-populate the store with the empty hashes
        let nodes = empty_hashes().collect();
        Self { nodes }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let mut hash = root;

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let bit = (index.value() >> i) & 1;
            hash = if bit == 0 { node.left } else { node.right }
        }

        Ok(hash)
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts at the sibling of the target leaf.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_path(&self, root: Word, index: NodeIndex) -> Result<MerkleProof, MerkleError> {
        let (value, path) = self.get_indexed_path(root, index)?;
        let path = path.into_values().rev().collect::<Vec<_>>();

        Ok(MerkleProof::new(value, MerklePath::new(path)))
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts below the root and contains all nodes in the opening
    /// all the way to the sibling of the target leaf.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    fn get_indexed_path(
        &self,
        root: Word,
        index: NodeIndex,
    ) -> Result<(Word, Map<NodeIndex, Word>), MerkleError> {
        let mut hash = root;
        let mut path = Map::<NodeIndex, Word>::new();

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        let mut pos = 0; // Root position at level 0
        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let bit = (index.value() >> i) & 1;
            let depth = index.depth() - i;
            hash = if bit == 0 {
                path.insert(NodeIndex::new(depth, pos * 2 + 1)?, node.right);
                pos = pos * 2;
                node.left
            } else {
                path.insert(NodeIndex::new(depth, pos * 2)?, node.left);
                pos = pos * 2 + 1;
                node.right
            }
        }

        Ok((hash, path))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets multiple node values at once with a single root transition.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn set_nodes(
        &mut self,
        root: Word,
        entries: impl IntoIterator<Item = (NodeIndex, Word)>,
    ) -> Result<Word, MerkleError> {
        self.nodes.get(&root).ok_or(MerkleError::RootNotInStore(root))?;

        // Keep track of affected ancestors to avoid recomputing nodes multiple times
        let mut ancestors: Vec<NodeIndex> = Vec::new();
        // Start with a guard value, all ancestors have depth < SMT_DEPTH
        let mut last_ancestor = NodeIndex::new_unchecked(SMT_DEPTH, 0);

        // Stash all new nodes until we know there are no errors
        let mut new_nodes: Map<Word, SmtNode> = Map::new();

        // Collect opening nodes and updated leaves
        let mut nodes_by_index = Map::<NodeIndex, Word>::new();
        for (index, leaf_hash) in entries {
            // Record all sibling nodes along the path from root to this index
            let (old_value, path_nodes) = self.get_indexed_path(root, index)?;
            if old_value == leaf_hash {
                continue;
            }
            nodes_by_index.extend(path_nodes);

            // Record the updated leaf value at this index
            nodes_by_index.insert(index, leaf_hash);

            if last_ancestor != index.parent() {
                last_ancestor = index.parent();
                ancestors.push(last_ancestor);
            }
        }

        if nodes_by_index.is_empty() {
            return Ok(root);
        }

        // Gather all ancestors up to the root (deduplicated)
        let mut index = 0;
        while index < ancestors.len() {
            let node = ancestors[index];
            if node.is_root() {
                break;
            }
            let parent = node.parent();
            if parent != last_ancestor {
                last_ancestor = parent;
                ancestors.push(last_ancestor);
            }
            index += 1;
        }

        for index in ancestors {
            let left_index = index.left_child();
            let right_index = index.right_child();

            let left_value = *nodes_by_index
                .get(&left_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(left_index))?;
            let right_value = *nodes_by_index
                .get(&right_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(right_index))?;

            let new_value = Rpo256::merge(&[left_value, right_value]);
            new_nodes.insert(
                new_value,
                SmtNode {
                    left: left_value,
                    right: right_value,
                    rc: 0,
                },
            );
            nodes_by_index.insert(index, new_value);
        }

        let new_root = nodes_by_index
            .get(&NodeIndex::root())
            .cloned()
            .ok_or(MerkleError::NodeIndexNotFoundInStore(root, NodeIndex::root()))?;

        // The update was computed successfully, update ref counts and insert into the store
        fn dfs(node: Word, store: &mut Map<Word, SmtNode>, new_nodes: &mut Map<Word, SmtNode>) {
            if node == Word::empty() {
                return;
            }
            if let Some(node) = store.get_mut(&node) {
                // this node already exists in the store, increase its reference count
                node.rc += 1;
            } else if let Some(mut smt_node) = new_nodes.remove(&node) {
                // this is a non-leaf node, insert it into the store and process its children
                smt_node.rc = 1;
                store.insert(node, smt_node);
                dfs(smt_node.left, store, new_nodes);
                dfs(smt_node.right, store, new_nodes);
            }
        }
        dfs(new_root, &mut self.nodes, &mut new_nodes);

        Ok(new_root)
    }

    /// Decreases the reference count of the specified node and releases memory if the count
    /// reached zero.
    ///
    /// Returns the terminal nodes (leaves) that were removed.
    fn remove_node(&mut self, node: Word) -> Vec<Word> {
        if node == Word::empty() {
            return vec![];
        }
        let Some(smt_node) = self.nodes.get_mut(&node) else {
            return vec![node];
        };
        smt_node.rc -= 1;
        if smt_node.rc > 0 {
            return vec![];
        }

        let left = smt_node.left;
        let right = smt_node.right;

        let mut result = Vec::new();
        result.extend(self.remove_node(left));
        result.extend(self.remove_node(right));
        return result;
    }

    /// Removes the specified roots from the store and releases memory used by now
    /// unreachable nodes.
    ///
    /// Returns the terminal nodes (leaves) that were removed.
    pub fn remove_roots(&mut self, roots: impl IntoIterator<Item = Word>) -> Vec<Word> {
        let mut removed_leaves = Vec::new();
        for root in roots {
            removed_leaves.extend(self.remove_node(root));
        }
        removed_leaves
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates empty hashes for all the subtrees of a tree with a max depth of 255.
fn empty_hashes() -> impl Iterator<Item = (Word, SmtNode)> {
    let subtrees = EmptySubtreeRoots::empty_hashes(SMT_DEPTH);
    subtrees
        .iter()
        .rev()
        .copied()
        .zip(subtrees.iter().rev().skip(1).copied())
        .map(|(child, parent)| (parent, SmtNode { left: child, right: child, rc: 1 }))
}
