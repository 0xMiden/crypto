use alloc::{boxed::Box, vec::Vec};
use core::mem;

use num::Integer;
use rayon::prelude::*;

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, Leaves,
    MerkleError, MutationSet, NodeIndex, Rpo256, SMT_DEPTH, Smt, SmtLeaf, SmtLeafError, SmtProof,
    SparseMerklePath, SparseMerkleTree, Word,
    concurrent::{
        MutatedSubtreeLeaves, PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter,
        build_subtree, fetch_sibling_pair, process_sorted_pairs_to_leaves,
    },
};
use crate::merkle::smt::{Map, NodeMutation, NodeMutations};

mod error;
pub use error::LargeSmtError;

#[cfg(test)]
mod tests;

mod subtree;
pub use subtree::{Subtree, SubtreeError};

mod storage;
pub use storage::{MemoryStorage, SmtStorage, StorageError, StorageUpdateParts, StorageUpdates};
#[cfg(feature = "rocksdb")]
pub use storage::{RocksDbConfig, RocksDbStorage};

// CONSTANTS
// ================================================================================================

/// Number of levels of the tree that are stored in memory
const IN_MEMORY_DEPTH: u8 = 24;

/// Number of nodes that are stored in memory
const NUM_IN_MEMORY_LEAVES: usize = (1 << IN_MEMORY_DEPTH) - 1;

/// Number of subtree levels below in-memory depth (24-64 in steps of 8)
const NUM_SUBTREE_LEVELS: usize = 5;

/// How many subtrees we buffer before flushing them to storage **during the
/// SMT construction phase**.
///
/// * This constant is **only** used while building a fresh tree; incremental updates use their own
///   per-batch sizing.
/// * Construction is all-or-nothing: if the write fails we abort and rebuild from scratch, so we
///   allow larger batches that maximise I/O throughput instead of fine-grained rollback safety.
const CONSTRUCTION_SUBTREE_BATCH_SIZE: usize = 10_000;

/// Subtree depths for the subtrees stored in storage
const SUBTREE_DEPTHS: [u8; 5] = [56, 48, 40, 32, 24];

// TYPES
// ================================================================================================

// LargeSmt
// ================================================================================================

/// A large-scale Sparse Merkle tree mapping 256-bit keys to 256-bit values, backed by pluggable
/// storage. Both keys and values are represented by 4 field elements.
///
/// Unlike the regular `Smt`, this implementation is designed for very large trees by using external
/// storage (such as RocksDB) for the bulk of the tree data, while keeping only the upper levels (up
/// to depth 24) in memory. This hybrid approach allows the tree to scale beyond memory limitations
/// while maintaining good performance for common operations.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
///
/// The tree structure:
/// - Depths 0-23: Stored in memory as a flat array for fast access
/// - Depths 24-64: Stored in external storage organized as subtrees for efficient batch operations
#[derive(Debug)]
pub struct LargeSmt<S: SmtStorage> {
    storage: S,
    in_memory_nodes: Vec<Option<Box<InnerNode>>>,
}

impl<S: SmtStorage> LargeSmt<S> {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [LargeSmt] backed by the provided storage.
    ///
    /// The SMT's root is fetched from the storage backend. If the storage is empty the SMT is
    /// initialized with the root of an empty tree. Otherwise, materializes in-memory nodes from
    /// the top subtrees.
    ///
    /// # Errors
    /// Returns an error if fetching the root or initial in-memory nodes from the storage fails.
    pub fn new(storage: S) -> Result<Self, LargeSmtError> {
        let root = storage.get_root()?.unwrap_or(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));

        let is_empty = !storage.has_leaves()?;

        // Initialize in-memory cache structure
        let mut in_memory_nodes: Vec<Option<Box<InnerNode>>> = vec![None; NUM_IN_MEMORY_LEAVES];

        // No leaves, return empty tree
        if is_empty {
            return Ok(Self { storage, in_memory_nodes });
        }

        let subtree_roots = storage.get_depth24()?;

        // convert subtree roots to SubtreeLeaf
        let mut leaf_subtrees: Vec<SubtreeLeaf> = subtree_roots
            .into_iter()
            .map(|(index, hash)| SubtreeLeaf { col: index, hash })
            .collect();
        leaf_subtrees.sort_by_key(|leaf| leaf.col);

        let mut subtree_leaves: Vec<Vec<SubtreeLeaf>> =
            SubtreeLeavesIter::from_leaves(&mut leaf_subtrees).collect();

        // build in-memory top of the tree
        for current_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!subtree_leaves.is_empty());

            for subtree_nodes in nodes {
                for (index, node) in subtree_nodes {
                    let memory_index = to_memory_index(&index);
                    in_memory_nodes[memory_index] = Some(Box::new(node));
                }
            }
        }

        // Check that the calculated root matches the root in storage
        assert_eq!(
            in_memory_nodes[0].as_ref().unwrap().hash(),
            root,
            "Tree reconstruction failed - root mismatch"
        );

        Ok(Self { storage, in_memory_nodes })
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        storage: S,
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, LargeSmtError> {
        let entries: Vec<(Word, Word)> = entries.into_iter().collect();

        if storage.has_leaves()? {
            panic!("Cannot create SMT with non-empty storage");
        }
        let mut tree = LargeSmt::new(storage)?;
        if entries.is_empty() {
            return Ok(tree);
        }
        tree.build_subtrees(entries)?;
        Ok(tree)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Result<Word, LargeSmtError> {
        Ok(self.storage.get_root()?.unwrap_or(Self::EMPTY_ROOT))
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the leaf count.
    pub fn num_leaves(&self) -> Result<usize, LargeSmtError> {
        Ok(self.storage.leaf_count()?)
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the entry count.
    pub fn num_entries(&self) -> Result<usize, LargeSmtError> {
        Ok(self.storage.entry_count()?)
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &Word) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &Word) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the root or leaf count.
    pub fn is_empty(&self) -> Result<bool, LargeSmtError> {
        let root = self.storage.get_root()?.unwrap_or(Self::EMPTY_ROOT);
        debug_assert_eq!(self.num_leaves()? == 0, root == Self::EMPTY_ROOT);
        Ok(root == Self::EMPTY_ROOT)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    /// Note: This iterator returns owned SmtLeaf values.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn leaves(
        &self,
    ) -> Result<impl Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>, LargeSmtError> {
        let iter = self.storage.iter_leaves()?;
        Ok(iter.map(|(idx, leaf)| (LeafIndex::new_max_depth(idx), leaf)))
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    /// Note: This iterator returns owned (Word, Word) tuples.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn entries(&self) -> Result<impl Iterator<Item = (Word, Word)>, LargeSmtError> {
        let leaves_iter = self.leaves()?;
        Ok(leaves_iter.flat_map(|(_, leaf)| {
            // Collect the (Word, Word) tuples into an owned Vec
            // This ensures they outlive the 'leaf' from which they are derived.
            let owned_entries: Vec<(Word, Word)> = leaf.entries().into_iter().copied().collect();
            // Return an iterator over this owned Vec
            owned_entries.into_iter()
        }))
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    ///
    /// # Errors
    /// Returns an error if the storage backend fails during iteration setup.
    pub fn inner_nodes(&self) -> Result<impl Iterator<Item = InnerNodeInfo> + '_, LargeSmtError> {
        // Pre-validate that storage is accessible
        let _ = self.storage.iter_subtrees()?;
        Ok(LargeSmtInnerNodeIterator::new(self))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    /// Returns an error if inserting the key-value pair would exceed
    /// [`MAX_LEAF_ENTRIES`](super::MAX_LEAF_ENTRIES) (1024 entries) in the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`Smt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{Felt, Word};
    /// # use miden_crypto::merkle::{Smt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt = Smt::new();
    /// let pair = (Word::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]).expect("compute_mutations ok");
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, LargeSmtError>
    where
        Self: Sized + Sync,
    {
        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_unstable_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| Self::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.dedup();
        leaf_indices.sort_unstable();

        // Get leaves from storage
        let leaves_from_storage =
            self.storage.get_leaves(&leaf_indices).expect("Failed to get leaves");

        // Map leaf indices to their corresponding leaves
        let leaf_map: Map<u64, SmtLeaf> = leaf_indices
            .into_iter()
            .zip(leaves_from_storage)
            .filter_map(|(index, maybe_leaf)| maybe_leaf.map(|leaf| (index, leaf)))
            .collect();

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut leaves, new_pairs) =
            self.sorted_pairs_to_mutated_leaves_with_preloaded_leaves(sorted_kv_pairs, leaf_map);

        // If no mutations, return an empty mutation set
        let old_root = self.root()?;
        if leaves.is_empty() {
            return Ok(MutationSet {
                old_root,
                new_root: old_root,
                node_mutations: NodeMutations::default(),
                new_pairs,
            });
        }

        let mut node_mutations = NodeMutations::default();

        // Process each depth level in reverse, stepping by the subtree depth
        for subtree_root_depth in
            (0..=SMT_DEPTH - SUBTREE_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            // Parallel processing of each subtree to generate mutations and roots
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    let subtree: Option<Subtree> = if subtree_root_depth < IN_MEMORY_DEPTH {
                        None
                    } else {
                        // Compute subtree root index
                        let subtree_root_index = NodeIndex::new_unchecked(
                            subtree_root_depth,
                            subtree_leaves[0].col >> SUBTREE_DEPTH,
                        );
                        self.storage
                            .get_subtree(subtree_root_index)
                            .expect("Storage error getting subtree in compute_mutations")
                    };
                    debug_assert!(subtree_leaves.is_sorted() && !subtree_leaves.is_empty());
                    self.build_subtree_mutations(
                        subtree_leaves,
                        SMT_DEPTH,
                        subtree_root_depth,
                        subtree,
                    )
                })
                .unzip();

            // Prepare leaves for the next depth level
            leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            // Aggregate all node mutations
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            debug_assert!(!leaves.is_empty());
        }

        let new_root = leaves[0][0].hash;

        // Create mutation set
        let mutation_set = MutationSet {
            old_root: self.root()?,
            new_root,
            node_mutations,
            new_pairs,
        };

        // There should be mutations and new pairs at this point
        debug_assert!(
            !mutation_set.node_mutations().is_empty() && !mutation_set.new_pairs().is_empty()
        );

        Ok(mutation_set)
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), LargeSmtError> {
        use NodeMutation::*;
        use rayon::prelude::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        let expected_root = self.root()?;
        if old_root != expected_root {
            return Err(LargeSmtError::Merkle(MerkleError::ConflictingRoots {
                expected_root,
                actual_root: old_root,
            }));
        }

        // Sort mutations
        let mut sorted_mutations: Vec<_> = Vec::from_iter(node_mutations);
        sorted_mutations.par_sort_unstable_by_key(|(index, _)| Subtree::find_subtree_root(*index));

        // Collect all unique subtree root indexes needed
        let mut subtree_roots_indices: Vec<NodeIndex> = sorted_mutations
            .iter()
            .filter_map(|(index, _)| {
                if index.depth() < IN_MEMORY_DEPTH {
                    None
                } else {
                    Some(Subtree::find_subtree_root(*index))
                }
            })
            .collect();
        subtree_roots_indices.dedup();

        // Read all subtrees at once
        let subtrees_from_storage = self.storage.get_subtrees(&subtree_roots_indices)?;

        // Map the subtrees
        let mut loaded_subtrees: Map<NodeIndex, Option<Subtree>> = subtree_roots_indices
            .into_iter()
            .zip(subtrees_from_storage)
            .map(|(root_index, subtree_opt)| {
                (root_index, Some(subtree_opt.unwrap_or_else(|| Subtree::new(root_index))))
            })
            .collect();

        // Process mutations
        for (index, mutation) in sorted_mutations {
            if index.depth() < IN_MEMORY_DEPTH {
                match mutation {
                    Removal => self.remove_inner_node(index),
                    Addition(node) => self.insert_inner_node(index, node),
                };
            } else {
                let subtree_root_index = Subtree::find_subtree_root(index);
                let subtree = loaded_subtrees
                    .get_mut(&subtree_root_index)
                    .expect("Subtree map entry must exist")
                    .as_mut()
                    .expect("Subtree must exist as it was either fetched or created");

                match mutation {
                    Removal => subtree.remove_inner_node(index),
                    Addition(node) => subtree.insert_inner_node(index, node),
                };
            }
        }

        // Go through subtrees, see if any are empty, and if so remove them
        for (_index, subtree) in loaded_subtrees.iter_mut() {
            if subtree.as_ref().is_some_and(|s| s.is_empty()) {
                *subtree = None;
            }
        }

        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = new_pairs.iter().map(|(k, v)| (*k, *v)).collect();
        sorted_kv_pairs.par_sort_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| Self::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.par_sort_unstable();
        leaf_indices.dedup();

        // Get leaves from storage
        let leaves = self.storage.get_leaves(&leaf_indices)?;

        // Map leaf indices to their corresponding leaves
        let mut leaf_map: Map<u64, Option<SmtLeaf>> =
            leaf_indices.into_iter().zip(leaves).collect();

        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        for (key, value) in new_pairs {
            let idx = Self::key_to_leaf_index(&key).value();
            // Get leaf
            let entry = leaf_map.entry(idx).or_insert(None);

            // New values is empty, handle deletion
            if value == Self::EMPTY_VALUE {
                if let Some(leaf) = entry {
                    // Leaf exists, handle deletion
                    if leaf.remove(key).1 {
                        // Key had previous value, decrement entry count
                        entry_count_delta -= 1;
                        if leaf.is_empty() {
                            // Leaf is now empty, remove it and decrement leaf count
                            *entry = None;
                            leaf_count_delta -= 1;
                        }
                    }
                }
            } else {
                // New value is not empty, handle update or create
                match entry {
                    Some(leaf) => {
                        // Leaf exists, handle update
                        if leaf.insert(key, value).expect("Failed to insert value").is_none() {
                            // Key had no previous value, increment entry count
                            entry_count_delta += 1;
                        }
                    },
                    None => {
                        // Leaf does not exist, create it
                        *entry = Some(SmtLeaf::Single((key, value)));
                        // Increment both entry and leaf count
                        entry_count_delta += 1;
                        leaf_count_delta += 1;
                    },
                }
            }
        }

        let updates = StorageUpdates::from_parts(
            leaf_map,
            loaded_subtrees,
            new_root,
            leaf_count_delta,
            entry_count_delta,
        );
        self.storage.apply(updates)?;
        Ok(())
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, LargeSmtError>
    where
        Self: Sized,
    {
        self.apply_mutations(mutations.clone())?;

        use NodeMutation::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        let mut reverse_mutations = NodeMutations::new();
        for (index, mutation) in node_mutations {
            match mutation {
                Removal => {
                    if let Some(node) = self.remove_inner_node(index) {
                        reverse_mutations.insert(index, Addition(node));
                    }
                },
                Addition(node) => {
                    if let Some(old_node) = self.insert_inner_node(index, node) {
                        reverse_mutations.insert(index, Addition(old_node));
                    } else {
                        reverse_mutations.insert(index, Removal);
                    }
                },
            }
        }

        let mut reverse_pairs = Map::new();
        for (key, value) in new_pairs {
            if let Some(old_value) = self.insert_value(key, value)? {
                reverse_pairs.insert(key, old_value);
            } else {
                reverse_pairs.insert(key, Self::EMPTY_VALUE);
            }
        }

        Ok(MutationSet {
            old_root: new_root,
            node_mutations: reverse_mutations,
            new_pairs: reverse_pairs,
            new_root: old_root,
        })
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    fn build_subtrees(&mut self, mut entries: Vec<(Word, Word)>) -> Result<(), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        self.build_subtrees_from_sorted_entries(entries)?;
        Ok(())
    }

    fn build_subtrees_from_sorted_entries(
        &mut self,
        entries: Vec<(Word, Word)>,
    ) -> Result<(), MerkleError> {
        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;

        if initial_leaves.is_empty() {
            return Ok(());
        }

        // Store the initial leaves
        self.storage.set_leaves(initial_leaves).expect("Failed to store initial leaves");

        // build deep (disk-backed) subtrees
        leaf_subtrees = std::thread::scope(|scope| {
            let (sender, receiver) = flume::bounded(CONSTRUCTION_SUBTREE_BATCH_SIZE);
            let storage: &S = &self.storage;

            scope.spawn(move || -> Result<(), MerkleError> {
                let mut subtrees: Vec<Subtree> =
                    Vec::with_capacity(CONSTRUCTION_SUBTREE_BATCH_SIZE);
                for subtree in receiver.iter() {
                    subtrees.push(subtree);
                    if subtrees.len() == CONSTRUCTION_SUBTREE_BATCH_SIZE {
                        let subtrees_clone = mem::take(&mut subtrees);
                        storage
                            .set_subtrees(subtrees_clone)
                            .expect("Writer thread failed to set subtrees");
                    }
                }
                storage.set_subtrees(subtrees).expect("Writer thread failed to set subtrees");
                Ok(())
            });

            for bottom_depth in (IN_MEMORY_DEPTH + SUBTREE_DEPTH..=SMT_DEPTH)
                .step_by(SUBTREE_DEPTH as usize)
                .rev()
            {
                let mut subtree_roots: Vec<SubtreeLeaf> = leaf_subtrees
                    .into_par_iter()
                    .map(|subtree_leaves| {
                        debug_assert!(subtree_leaves.is_sorted());
                        debug_assert!(!subtree_leaves.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree_leaves, SMT_DEPTH, bottom_depth);

                        let subtree_root_index =
                            NodeIndex::new(bottom_depth - SUBTREE_DEPTH, subtree_root.col).unwrap();
                        let mut subtree = Subtree::new(subtree_root_index);
                        for (index, node) in nodes {
                            subtree.insert_inner_node(index, node);
                        }
                        sender.send(subtree).expect("Flume channel disconnected unexpectedly");
                        subtree_root
                    })
                    .collect();
                leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
                debug_assert!(!leaf_subtrees.is_empty());
            }

            drop(sender);
            leaf_subtrees
        });

        // build top of the tree (in-memory only, normal insert)
        for bottom_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, bottom_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!leaf_subtrees.is_empty());

            for subtree_nodes in nodes {
                self.insert_inner_nodes_batch(subtree_nodes.into_iter());
            }
        }
        self.set_root(self.get_inner_node(NodeIndex::root()).hash());
        Ok(())
    }

    // MUTATIONS
    // --------------------------------------------------------------------------------------------

    /// Computes leaves from a set of key-value pairs and current leaf values.
    /// Derived from `sorted_pairs_to_leaves`
    fn sorted_pairs_to_mutated_leaves_with_preloaded_leaves(
        &self,
        pairs: Vec<(Word, Word)>,
        leaf_map: Map<u64, SmtLeaf>,
    ) -> (MutatedSubtreeLeaves, Map<Word, Word>) {
        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = Map::new();

        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let leaf_index = LeafIndex::<SMT_DEPTH>::from(leaf_pairs[0].0);
            let mut leaf = leaf_map
                .get(&leaf_index.value())
                .cloned()
                .unwrap_or_else(|| SmtLeaf::new_empty(leaf_pairs[0].0.into()));

            let mut leaf_changed = false;
            for (key, value) in leaf_pairs {
                // Check if the value has changed
                let old_value = new_pairs.get(&key).cloned().unwrap_or_else(|| {
                    // Safe to unwrap: `leaf_pairs` contains keys all belonging to this leaf.
                    // `SmtLeaf::get_value()` only returns `None` if the key does not belong to the
                    // leaf, which cannot happen due to the sorting/grouping
                    // logic in `process_sorted_pairs_to_leaves()`.
                    leaf.get_value(&key).unwrap()
                });

                if value != old_value {
                    // Update the leaf and track the new key-value pair
                    leaf = self
                        .construct_prospective_leaf(leaf, &key, &value)
                        .expect("Failed to construct prospective leaf");
                    new_pairs.insert(key, value);
                    leaf_changed = true;
                }
            }

            if leaf_changed {
                // Only return the leaf if it actually changed
                Ok(Some(leaf))
            } else {
                // Return None if leaf hasn't changed
                Ok(None)
            }
        });
        // The closure is the only possible source of errors.
        // Since it never returns an error - only `Ok(Some(_))` or `Ok(None)` - we can safely assume
        // `accumulator` is always `Ok(_)`.
        (
            accumulator.expect("process_sorted_pairs_to_leaves never fails").leaves,
            new_pairs,
        )
    }

    /// Computes the node mutations and the root of a subtree
    fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        tree_depth: u8,
        subtree_root_depth: u8,
        subtree: Option<Subtree>,
    ) -> (NodeMutations, SubtreeLeaf)
    where
        Self: Sized,
    {
        let bottom_depth = subtree_root_depth + SUBTREE_DEPTH;

        debug_assert!(bottom_depth <= tree_depth);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let mut node_mutations: NodeMutations = Default::default();
        let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);

        for current_depth in (subtree_root_depth..bottom_depth).rev() {
            debug_assert!(current_depth <= bottom_depth);

            let next_depth = current_depth + 1;
            let mut iter = leaves.drain(..).peekable();

            while let Some(first_leaf) = iter.next() {
                // This constructs a valid index because next_depth will never exceed the depth of
                // the tree.
                let parent_index = NodeIndex::new_unchecked(next_depth, first_leaf.col).parent();
                let parent_node = if let Some(ref sub) = subtree {
                    sub.get_inner_node(parent_index).unwrap_or_else(|| {
                        EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                    })
                } else if subtree_root_depth >= IN_MEMORY_DEPTH {
                    EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                } else {
                    self.get_inner_node(parent_index)
                };
                let combined_node = fetch_sibling_pair(&mut iter, first_leaf, parent_node);
                let combined_hash = combined_node.hash();

                let &empty_hash = EmptySubtreeRoots::entry(tree_depth, current_depth);

                // Add the parent node even if it is empty for proper upward updates
                next_leaves.push(SubtreeLeaf {
                    col: parent_index.value(),
                    hash: combined_hash,
                });

                node_mutations.insert(
                    parent_index,
                    if combined_hash != empty_hash {
                        NodeMutation::Addition(combined_node)
                    } else {
                        NodeMutation::Removal
                    },
                );
            }
            drop(iter);
            leaves = mem::take(&mut next_leaves);
        }

        debug_assert_eq!(leaves.len(), 1);
        let root_leaf = leaves.pop().unwrap();
        (node_mutations, root_leaf)
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    // Inserts batch of upper inner nodes
    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        for (index, node) in nodes {
            if index.depth() < IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                self.in_memory_nodes[memory_index] = Some(Box::new(node));
            }
        }
    }
}

impl<S: SmtStorage> SparseMerkleTree<SMT_DEPTH> for LargeSmt<S> {
    type Key = Word;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        _inner_nodes: InnerNodes,
        _leaves: Leaves,
        _root: Word,
    ) -> Result<Self, MerkleError> {
        // This method is not supported
        panic!("LargeSmt::from_raw_parts is not supported");
    }

    fn root(&self) -> Word {
        self.storage.get_root().ok().flatten().unwrap_or(Self::EMPTY_ROOT)
    }

    fn set_root(&mut self, root: Word) {
        self.storage.set_root(root).expect("Failed to set root");
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            return match &self.in_memory_nodes[memory_index] {
                Some(boxed_node) => (**boxed_node).clone(),
                None => EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()),
            };
        }

        self.storage
            .get_inner_node(index)
            .expect("Failed to get inner node")
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            let old_option_box = self.in_memory_nodes[i].replace(Box::new(inner_node));
            return old_option_box.map(|boxed_node| *boxed_node);
        }
        self.storage
            .set_inner_node(index, inner_node)
            .expect("Failed to store inner node")
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            let old_option_box = self.in_memory_nodes[memory_index].take();
            return old_option_box.map(|boxed_node| *boxed_node);
        }
        self.storage.remove_inner_node(index).expect("Failed to remove inner node")
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Result<Self::Value, MerkleError> {
        let old_value = self.get_value(&key);
        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let mutations = self
            .compute_mutations([(key, value)])
            .expect("Failed to compute mutations in insert");
        self.apply_mutations(mutations).expect("Failed to apply mutations in insert");

        Ok(old_value)
    }

    fn insert_value(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, MerkleError> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        let index = Self::key_to_leaf_index(&key).value();
        if value != Self::EMPTY_VALUE {
            match self.storage.insert_value(index, key, value) {
                Ok(prev) => Ok(prev),
                Err(StorageError::Leaf(SmtLeafError::TooManyLeafEntries { actual })) => {
                    Err(MerkleError::TooManyLeafEntries { actual })
                },
                Err(_) => {
                    panic!("Storage error during insert_value");
                },
            }
        } else {
            Ok(self.storage.remove_value(index, key).expect("Failed to remove value"))
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);
        match self.storage.get_leaf(leaf_pos.value()) {
            Ok(Some(leaf)) => leaf.get_value(key).unwrap_or_default(),
            Ok(None) => EMPTY_WORD,
            Err(_) => {
                panic!("Storage error during get_leaf in get_value");
            },
        }
    }

    fn get_leaf(&self, key: &Word) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();
        match self.storage.get_leaf(leaf_pos) {
            Ok(Some(leaf)) => leaf,
            Ok(None) => SmtLeaf::new_empty((*key).into()),
            Err(_) => {
                panic!("Storage error during get_leaf in get_leaf");
            },
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> Word {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        mut existing_leaf: SmtLeaf,
        key: &Word,
        value: &Word,
    ) -> Result<SmtLeaf, SmtLeafError> {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => Ok(SmtLeaf::new_single(*key, *value)),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value)?;
                } else {
                    existing_leaf.remove(*key);
                }

                Ok(existing_leaf)
            },
        }
    }

    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf = self.get_leaf(key);

        let mut idx: NodeIndex = LeafIndex::from(*key).into();

        let subtree_roots: Vec<NodeIndex> = (0..NUM_SUBTREE_LEVELS)
            .scan(idx.parent(), |cursor, _| {
                let subtree_root = Subtree::find_subtree_root(*cursor);
                *cursor = subtree_root.parent();
                Some(subtree_root)
            })
            .collect();
        // cache subtrees in memory
        let mut cache = Map::<NodeIndex, Subtree>::new();
        for &root in &subtree_roots {
            let subtree =
                match self.storage.get_subtree(root).expect("storage error fetching subtree") {
                    Some(st) => st,
                    None => Subtree::new(root),
                };
            cache.insert(root, subtree);
        }
        let mut path = Vec::with_capacity(idx.depth() as usize);
        while idx.depth() > 0 {
            let is_right = idx.is_value_odd();
            idx = idx.parent();

            let sibling_hash = if idx.depth() < IN_MEMORY_DEPTH {
                // top levels in memory
                let InnerNode { left, right } = self.get_inner_node(idx);
                if is_right { left } else { right }
            } else {
                // deep levels come from our 5 preloaded subtrees
                let root = Subtree::find_subtree_root(idx);
                let subtree = &cache[&root];
                let InnerNode { left, right } = subtree
                    .get_inner_node(idx)
                    .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, idx.depth()));
                if is_right { left } else { right }
            };

            path.push(sibling_hash);
        }

        let merkle_path =
            SparseMerklePath::from_sized_iter(path).expect("failed to convert to SparseMerklePath");
        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: SparseMerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl<S: SmtStorage> PartialEq for LargeSmt<S> {
    /// Compares two LargeSmt instances based on their root hash and metadata.
    ///
    /// Note: This comparison only checks the root hash and counts, not the underlying
    /// storage contents. Two SMTs with the same root should be cryptographically
    /// equivalent, but this doesn't verify the storage backends are identical.
    fn eq(&self, other: &Self) -> bool {
        self.root().unwrap() == other.root().unwrap()
            && self.num_leaves().unwrap() == other.num_leaves().unwrap()
            && self.num_entries().unwrap() == other.num_entries().unwrap()
    }
}

impl<S: SmtStorage> Eq for LargeSmt<S> {}

// Note: Clone is intentionally not implemented for LargeSmt because:
// 1. Cloning would only clone the in-memory portion and share storage via Arc
// 2. This doesn't actually clone the underlying disk data, which is misleading
// 3. Users should be explicit about sharing LargeSmt instances via Arc if needed

fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() < IN_MEMORY_DEPTH);
    debug_assert!(index.value() < (1 << index.depth()));
    ((1usize << index.depth()) - 1) + index.value() as usize
}

// ITERATORS
// ================================================================================================

enum InnerNodeIteratorState<'a> {
    InMemory {
        current_index: usize,
        large_smt_in_memory_nodes: &'a Vec<Option<Box<InnerNode>>>,
    },
    Subtree {
        subtree_iter: Box<dyn Iterator<Item = Subtree> + 'a>,
        current_subtree_node_iter: Option<Box<dyn Iterator<Item = InnerNodeInfo> + 'a>>,
    },
    Done,
}

pub struct LargeSmtInnerNodeIterator<'a, S: SmtStorage> {
    large_smt: &'a LargeSmt<S>,
    state: InnerNodeIteratorState<'a>,
}

impl<'a, S: SmtStorage> LargeSmtInnerNodeIterator<'a, S> {
    fn new(large_smt: &'a LargeSmt<S>) -> Self {
        // in-memory nodes should never be empty
        Self {
            large_smt,
            state: InnerNodeIteratorState::InMemory {
                current_index: 0,
                large_smt_in_memory_nodes: &large_smt.in_memory_nodes,
            },
        }
    }
}

impl<S: SmtStorage> Iterator for LargeSmtInnerNodeIterator<'_, S> {
    type Item = InnerNodeInfo;

    /// Returns the next inner node info in the tree.
    ///
    /// The iterator operates in three phases:
    /// 1. InMemory: Iterates through the in-memory nodes (depths 0-IN_MEMORY_DEPTH-1)
    /// 2. Subtree: Iterates through nodes in storage subtrees (depths IN_MEMORY_DEPTH-SMT_DEPTH)
    /// 3. Done: No more nodes to iterate
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                // Phase 1: Process in-memory nodes (depths 0-24)
                InnerNodeIteratorState::InMemory { current_index, large_smt_in_memory_nodes } => {
                    while *current_index < large_smt_in_memory_nodes.len() {
                        let flat_idx = *current_index;
                        *current_index += 1;

                        if let Some(node) = &large_smt_in_memory_nodes[flat_idx] {
                            return Some(InnerNodeInfo {
                                value: Rpo256::merge(&[node.left, node.right]),
                                left: node.left,
                                right: node.right,
                            });
                        }
                    }

                    // All in-memory nodes processed. Transition to Phase 2: Subtree iteration
                    match self.large_smt.storage.iter_subtrees() {
                        Ok(subtree_iter) => {
                            self.state = InnerNodeIteratorState::Subtree {
                                subtree_iter,
                                current_subtree_node_iter: None,
                            };
                            continue; // Start processing subtrees immediately
                        },
                        Err(_e) => {
                            // Storage error occurred - we should propagate this properly
                            // For now, transition to Done state to avoid infinite loops
                            self.state = InnerNodeIteratorState::Done;
                            return None;
                        },
                    }
                },
                // Phase 2: Process storage subtrees (depths 25-64)
                InnerNodeIteratorState::Subtree { subtree_iter, current_subtree_node_iter } => {
                    loop {
                        // First, try to get the next node from current subtree
                        if let Some(node_iter) = current_subtree_node_iter
                            && let Some(info) = node_iter.as_mut().next()
                        {
                            return Some(info);
                        }

                        // Current subtree exhausted, move to next subtree
                        match subtree_iter.next() {
                            Some(next_subtree) => {
                                let infos: Vec<InnerNodeInfo> =
                                    next_subtree.iter_inner_node_info().collect();
                                *current_subtree_node_iter = Some(Box::new(infos.into_iter()));
                            },
                            None => {
                                self.state = InnerNodeIteratorState::Done;
                                return None; // All subtrees processed
                            },
                        }
                    }
                },
                InnerNodeIteratorState::Done => {
                    return None; // Iteration finished.
                },
            }
        }
    }
}
