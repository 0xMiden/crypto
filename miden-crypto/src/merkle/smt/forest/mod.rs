use alloc::{
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};

use super::{EmptySubtreeRoots, MerkleError, NodeIndex, SmtLeaf, SmtProof, Word};
use crate::{
    Map,
    merkle::{
        LeafIndex, SmtLeafError, SmtProofError,
        smt::{SMT_DEPTH, forest::store::SmtStore},
    },
};

mod store;

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// An in-memory data collection of sparse Merkle trees (SMTs).
///
/// Each SMT in the forest is identified by its root hash. The forest stores all leaves of all SMTs
/// in the forest, as well as all Merkle paths required to prove membership of any leaf in any SMT.
///
///
/// Example usage:
///
/// ```rust
/// use miden_crypto::{
///     Felt, Map, ONE, WORD_SIZE, ZERO,
///     merkle::{
///         forest::{EmptySubtreeRoots, SmtForest, Word},
///         int_to_node,
///         smt::{MAX_LEAF_ENTRIES, SMT_DEPTH},
///     },
/// };
///
/// // Create a new SMT forest
/// let mut forest = SmtForest::new();
///
/// // Insert a key-value pair into an SMT with an empty root
/// let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
/// let key = Word::new([ZERO; WORD_SIZE]);
/// let value = Word::new([ONE; WORD_SIZE]);
/// let new_root = forest.insert(empty_tree_root, key, value).unwrap();
///
/// // Insert multiple key-value pairs
/// let mut entries = Map::new();
/// for i in 0..MAX_LEAF_ENTRIES {
///     let key = Word::new([Felt::new(i as u64); WORD_SIZE]);
///     let value = Word::new([Felt::new((i + 1) as u64); WORD_SIZE]);
///     entries.insert(key, value);
/// }
/// let new_root = forest.batch_insert(new_root, &entries).unwrap();
///
/// // Open a proof for the inserted key
/// let proof = forest.open(new_root, key).unwrap();
///
/// // Prune older roots to release memory used by old SMT instances
/// forest.pop_roots(10);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SmtForest {
    /// Roots of all SMTs in this forest. Any time an SMT in this forest is updated, we add a new
    /// root to this set.
    roots: BTreeSet<Word>,

    /// Chronological history of SMT roots used for pruning.
    root_history: VecDeque<Word>,

    /// Stores Merkle paths for all SMTs in this forest.
    store: SmtStore,

    /// Leaves of all SMTs stored in this forest
    leaves: Map<Word, SmtLeaf>,
}

impl Default for SmtForest {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtForest {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `SmtForest` instance.
    pub fn new() -> SmtForest {
        let roots = BTreeSet::new();
        let root_history = VecDeque::new();
        let store = SmtStore::new();
        let leaves = Map::new();

        SmtForest { roots, root_history, store, leaves }
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an opening for the specified key in the SMT with the specified root.
    ///
    /// Returns an error if an SMT with this root is not in the forest, or if the forest does
    /// not have sufficient data to provide an opening for the specified key.
    pub fn open(&self, root: Word, key: Word) -> Result<SmtProof, MerkleError> {
        if !self.contains_root(root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        let leaf_index = NodeIndex::new_unchecked(SMT_DEPTH, key[3].as_int());

        let proof = self.store.get_path(root, leaf_index)?;
        let path = proof.path.try_into()?;
        let leaf = proof.value;

        let Some(leaf) = self.leaves.get(&leaf).cloned() else {
            return Err(MerkleError::UntrackedKey(key));
        };

        SmtProof::new(path, leaf).map_err(|error| match error {
            SmtProofError::InvalidMerklePathLength(depth) => MerkleError::InvalidPathLength(depth),
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified key-value pair into an SMT with the specified root. This would also
    /// add a new root to the forest.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, these is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn insert(&mut self, root: Word, key: Word, value: Word) -> Result<Word, MerkleError> {
        self.batch_insert(root, vec![(key, value)].into_iter())
    }

    /// Inserts the specified key-value pairs into an SMT with the specified root. This would also
    /// add a new root to the forest.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, these is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn batch_insert(
        &mut self,
        root: Word,
        entries: impl Iterator<Item = (Word, Word)> + Clone,
    ) -> Result<Word, MerkleError> {
        if !self.contains_root(root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        // Find all affected leaf indices
        let indices = entries.clone().map(|(key, _)| key[3].as_int()).collect::<BTreeSet<_>>();

        // Create new SmtLeaf objects for updated key-value pairs
        let mut new_leaves = Map::new();
        for index in indices {
            let node_index = NodeIndex::new_unchecked(SMT_DEPTH, index);
            let current_hash = self.store.get_node(root, node_index)?;

            let current_leaf = self.leaves.get(&current_hash).cloned().unwrap_or_else(|| {
                let leaf_index = LeafIndex::new_max_depth(index);
                SmtLeaf::new_empty(leaf_index)
            });

            new_leaves.insert(index, (current_hash, current_leaf));
        }
        for (key, value) in entries {
            let index = key[3].as_int();
            let (_old_hash, leaf) = new_leaves.get_mut(&index).unwrap();
            leaf.insert(key, value).map_err(to_merkle_error)?;
        }

        // Calculate new leaf hashes, skip processing unchanged leaves
        new_leaves = new_leaves
            .into_iter()
            .filter_map(|(key, (old_hash, leaf))| {
                let new_hash = leaf.hash();
                if new_hash == old_hash {
                    None
                } else {
                    Some((key, (new_hash, leaf)))
                }
            })
            .collect();

        // Update MerkleStore with new leaf hashes
        let new_leaf_entries = new_leaves
            .iter()
            .map(|(index, leaf)| (NodeIndex::new_unchecked(SMT_DEPTH, *index), leaf.0))
            .collect::<Vec<_>>();
        let new_root = self.store.set_nodes(root, new_leaf_entries)?;

        // Update successful, insert new leaves into the forest
        for (leaf_hash, leaf) in new_leaves.into_values() {
            self.leaves.insert(leaf_hash, leaf);
        }
        self.roots.insert(new_root);
        self.root_history.push_back(new_root);

        Ok(new_root)
    }

    /// Removes the specified number of oldest roots from the forest.
    /// Releases memory used by nodes and leaves that are no longer reachable.
    pub fn pop_roots(&mut self, count: usize) {
        let roots = self.root_history.drain(..count).collect::<Vec<_>>();
        for root in &roots {
            self.roots.remove(root);
        }
        for leaf in self.store.remove_roots(roots.into_iter()) {
            self.leaves.remove(&leaf);
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Checks if the forest contains the specified root.
    fn contains_root(&self, root: Word) -> bool {
        self.roots.contains(&root)
            || (self.roots.is_empty() && *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root)
    }
}

fn to_merkle_error(err: SmtLeafError) -> MerkleError {
    match err {
        SmtLeafError::TooManyLeafEntries { actual } => MerkleError::TooManyLeafEntries { actual },
        _ => unreachable!("other SmtLeafError variants should not be possible here"),
    }
}
