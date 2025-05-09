use alloc::{boxed::Box, vec::Vec};
use core::mem;
use std::sync::Arc;

use num::Integer;
use rayon::prelude::*;

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, Leaves,
    MerkleError, MerklePath, MutationSet, NodeIndex, Rpo256, RpoDigest, SMT_DEPTH, Smt, SmtLeaf,
    SmtProof, SparseMerkleTree, Word,
    concurrent::{
        MutatedSubtreeLeaves, PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter,
        build_subtree, fetch_sibling_pair, process_sorted_pairs_to_leaves,
    },
};
use crate::merkle::smt::{NodeMutation, NodeMutations, UnorderedMap};

#[cfg(test)]
mod tests;

mod subtree;
use subtree::Subtree;

mod storage;
#[cfg(feature = "rocksdb")]
pub use storage::RocksDbStorage;
pub use storage::{MemoryStorage, SmtStorage};

// CONSTANTS
// ================================================================================================

const IN_MEMORY_DEPTH: u8 = 24;

// TYPES
// ================================================================================================

// LargeSmt
// ================================================================================================

/// Sparse Merkle tree mapping 256-bit keys to 256-bit values. Both keys and values are represented
/// by 4 field elements.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
#[derive(Debug)]
pub struct LargeSmt<S: SmtStorage + 'static> {
    root: RpoDigest,
    storage: Arc<S>,
    in_memory_nodes: Vec<Option<InnerNode>>,
    in_memory_count: usize,
}

impl<S: SmtStorage + 'static> LargeSmt<S> {
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
    pub fn new(storage: S) -> Result<Self, MerkleError> {
        let root = storage
            .get_root()
            .expect("Failed to get root")
            .unwrap_or(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));

        let leaf_count = storage.get_leaf_count().expect("Failed to get leaf count");

        // Initialize in-memory cache structure
        let num_in_memory_nodes = (1 << (IN_MEMORY_DEPTH + 1)) - 1;
        let mut in_memory_nodes: Vec<Option<InnerNode>> = vec![None; num_in_memory_nodes]; // Ensure type annotation
        let mut in_memory_count = 0;

        // If there are leaves, materialize the in-memory nodes
        if leaf_count > 0 {
            let subtree_roots = storage
                .get_subtree_roots_at_depth(IN_MEMORY_DEPTH)
                .expect("Failed to get subtree roots");

            // convert subtree roots to SubtreeLeaf
            let mut leaf_subtrees: Vec<SubtreeLeaf> = subtree_roots
                .into_iter()
                .map(|(index, hash)| SubtreeLeaf { col: index, hash })
                .collect();
            leaf_subtrees.sort_by_key(|leaf| leaf.col);

            let mut subtree_leaves: Vec<Vec<SubtreeLeaf>> =
                SubtreeLeavesIter::from_leaves(&mut leaf_subtrees).collect();
            for current_depth in
                (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
            {
                let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) =
                    subtree_leaves
                        .into_par_iter()
                        .map(|subtree| {
                            debug_assert!(subtree.is_sorted());
                            debug_assert!(!subtree.is_empty());
                            let (nodes, subtree_root) =
                                build_subtree(subtree, SMT_DEPTH, current_depth);
                            (nodes, subtree_root)
                        })
                        .unzip();
                subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
                debug_assert!(!subtree_leaves.is_empty());

                for subtree_nodes in nodes {
                    for (index, node) in subtree_nodes {
                        let memory_index = to_memory_index(&index);
                        in_memory_nodes[memory_index] = Some(node);
                        in_memory_count += 1;
                    }
                }
            }
            assert_eq!(in_memory_nodes[0].clone().unwrap().hash(), root);
        }
        Ok(Self {
            root,
            storage: Arc::new(storage),
            in_memory_nodes,
            in_memory_count,
        })
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
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        let entries: Vec<(RpoDigest, Word)> = entries.into_iter().collect();

        if storage.get_leaf_count().expect("Failed to get leaf count") > 0 {
            panic!("Cannot create SMT with non-empty storage");
        }
        let mut tree = LargeSmt::new(storage).expect("Failed to create SMT");
        if entries.is_empty() {
            return Ok(tree);
        }
        tree.build_subtrees(entries)?;
        Ok(tree)
    }

    /// Returns a new [`Smt`] instantiated from already computed leaves and nodes.
    ///
    /// This function performs minimal consistency checking. It is the caller's responsibility to
    /// ensure the passed arguments are correct and consistent with each other.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if `root` does not match the root node in
    /// `inner_nodes`.
    pub fn from_raw_parts(inner_nodes: InnerNodes, leaves: Leaves, root: RpoDigest) -> Self {
        // Our particular implementation of `from_raw_parts()` never returns `Err`.
        <Self as SparseMerkleTree<SMT_DEPTH>>::from_raw_parts(inner_nodes, leaves, root).unwrap()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> RpoDigest {
        <Self as SparseMerkleTree<SMT_DEPTH>>::root(self)
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.storage.get_leaf_count().expect("Storage error getting leaf count")
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    pub fn num_entries(&self) -> usize {
        self.storage.get_entry_count().expect("Storage error getting entry count")
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &RpoDigest) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &RpoDigest) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &RpoDigest) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.num_leaves() == 0, self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    /// Note: This iterator returns owned SmtLeaf values.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)> {
        self.storage
            .iter_leaves()
            .expect("Storage error iterating leaves")
            .map(|(idx, leaf)| (LeafIndex::new_max_depth(idx), leaf))
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    /// Note: This iterator returns owned (RpoDigest, Word) tuples.
    pub fn entries(&self) -> impl Iterator<Item = (RpoDigest, Word)> {
        self.leaves() // Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)
            .flat_map(|(_, leaf)| { // leaf is SmtLeaf (owned)
                // Collect the (RpoDigest, Word) tuples into an owned Vec
                // This ensures they outlive the 'leaf' from which they are derived.
                let owned_entries: Vec<(RpoDigest, Word)> =
                    leaf.entries().iter().map(|double_ref| **double_ref).collect();
                // Return an iterator over this owned Vec
                owned_entries.into_iter()
            })
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        LargeSmtInnerNodeIterator::new(self)
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Word {
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
    /// # use miden_crypto::{hash::rpo::RpoDigest, Felt, Word};
    /// # use miden_crypto::merkle::{Smt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt = Smt::new();
    /// let pair = (RpoDigest::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]);
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word>
    where
        Self: Sized + Sync,
    {
        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_unstable_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut leaves, new_pairs) = self.sorted_pairs_to_mutated_leaves(sorted_kv_pairs);

        // If no mutations, return an empty mutation set
        if leaves.is_empty() {
            return MutationSet {
                old_root: self.root(),
                new_root: self.root(),
                node_mutations: NodeMutations::default(),
                new_pairs,
            };
        }

        let mut node_mutations = NodeMutations::default();

        // Process each depth level in reverse, stepping by the subtree depth
        for depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            // Parallel processing of each subtree to generate mutations and roots
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    let subtree: Option<Subtree> = if depth >= IN_MEMORY_DEPTH {
                        let index = NodeIndex::new_unchecked(depth, subtree_leaves[0].col);
                        let subtree_root_index = Subtree::find_subtree_root(index.parent());
                        self.storage
                            .get_subtree(subtree_root_index)
                            .expect("Storage error getting subtree in compute_mutations")
                    } else {
                        None
                    };
                    debug_assert!(subtree_leaves.is_sorted() && !subtree_leaves.is_empty());
                    self.build_subtree_mutations(subtree_leaves, SMT_DEPTH, depth, subtree)
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
            old_root: self.root(),
            new_root,
            node_mutations,
            new_pairs,
        };

        // There should be mutations and new pairs at this point
        debug_assert!(
            !mutation_set.node_mutations().is_empty() && !mutation_set.new_pairs().is_empty()
        );

        mutation_set
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
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<(), MerkleError> {
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
        if old_root != self.root() {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: old_root,
            });
        }

        // 1. Sort mutations
        let mut sorted_mutations: Vec<_> = node_mutations.into_iter().collect();
        sorted_mutations.par_sort_unstable_by_key(|(index, _)| Subtree::find_subtree_root(*index));

        // 2. Collect all unique subtree root indexes needed
        let mut subtree_roots_indices = Vec::new();
        for (index, _) in &sorted_mutations {
            if index.depth() >= IN_MEMORY_DEPTH {
                subtree_roots_indices.push(Subtree::find_subtree_root(*index));
            }
        }
        subtree_roots_indices.dedup();

        // 4. Read all subtrees at once
        let subtrees = self
            .storage
            .get_subtrees(&subtree_roots_indices)
            .expect("Failed to get subtrees in apply_mutations");

        // 4. Map the subtrees
        let mut loaded_subtrees = UnorderedMap::new();
        for (root_index, subtree_opt) in subtree_roots_indices.into_iter().zip(subtrees.into_iter())
        {
            match subtree_opt {
                Some(subtree_content) => loaded_subtrees.insert(root_index, subtree_content),
                None => loaded_subtrees.insert(root_index, Subtree::new(root_index)),
            };
        }

        // 5. Now process mutations
        for (index, mutation) in sorted_mutations {
            if index.depth() >= IN_MEMORY_DEPTH {
                let subtree_root_index = Subtree::find_subtree_root(index);
                let subtree = loaded_subtrees
                    .get_mut(&subtree_root_index)
                    .expect("Subtree must be loaded as it was fetched or created");

                match mutation {
                    Removal => subtree.remove_inner_node(index),
                    Addition(node) => subtree.insert_inner_node(index, node),
                };
            } else {
                // This is the in-memory piece
                match mutation {
                    Removal => self.remove_inner_node(index),
                    Addition(node) => self.insert_inner_node(index, node),
                };
            }
        }

        self.storage
            .set_subtrees(loaded_subtrees.values().cloned().collect())
            .expect("Failed to set subtrees in apply_mutations");

        for (key, value) in new_pairs {
            self.insert_value(key, value);
        }
        self.set_root(new_root);

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
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, RpoDigest, Word>, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations_with_reversion(self, mutations)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    fn build_subtrees(&mut self, mut entries: Vec<(RpoDigest, Word)>) -> Result<(), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        self.build_subtrees_from_sorted_entries(entries)?;
        Ok(())
    }

    fn build_subtrees_from_sorted_entries(
        &mut self,
        entries: Vec<(RpoDigest, Word)>,
    ) -> Result<(), MerkleError> {
        use flume;

        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;

        if initial_leaves.is_empty() {
            return Ok(());
        }

        // Store the initial leaves
        self.storage.set_leaves(initial_leaves).expect("Failed to store initial leaves");

        // Setup background writer thread
        let (sender, receiver) = flume::bounded(10240);
        let storage_clone = Arc::clone(&self.storage);

        let writer_handle = std::thread::spawn(move || -> Result<(), MerkleError> {
            let mut subtrees: Vec<Subtree> = Vec::with_capacity(10000);
            for subtree in receiver.iter() {
                subtrees.push(subtree);
                if subtrees.len() == 10000 {
                    let subtrees_clone = mem::take(&mut subtrees);
                    storage_clone
                        .set_subtrees(subtrees_clone)
                        .expect("Writer thread failed to set subtrees");
                }
            }
            storage_clone
                .set_subtrees(subtrees)
                .expect("Writer thread failed to set subtrees");
            Ok(())
        });

        for current_depth in (IN_MEMORY_DEPTH + SUBTREE_DEPTH..=SMT_DEPTH)
            .step_by(SUBTREE_DEPTH as usize)
            .rev()
        {
            let mut subtree_roots: Vec<SubtreeLeaf> = leaf_subtrees
                .into_par_iter()
                .map(|subtree_leaves| {
                    debug_assert!(subtree_leaves.is_sorted());
                    debug_assert!(!subtree_leaves.is_empty());
                    let (nodes, subtree_root) =
                        build_subtree(subtree_leaves, SMT_DEPTH, current_depth);

                    let subtree_root_index =
                        NodeIndex::new(current_depth - SUBTREE_DEPTH, subtree_root.col).unwrap();
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

        // Finalize: Drop sender, wait for writer thread to finish
        drop(sender);
        let _ = writer_handle.join().expect("Writer thread panicked");
        // -----------------------------------------------

        // Build top subtrees (in-memory only, normal insert)
        for current_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) =
                leaf_subtrees
                    .into_par_iter()
                    .map(|subtree| {
                        debug_assert!(subtree.is_sorted());
                        debug_assert!(!subtree.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree, SMT_DEPTH, current_depth);
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
    fn sorted_pairs_to_mutated_leaves(
        &self,
        pairs: Vec<(RpoDigest, Word)>,
    ) -> (MutatedSubtreeLeaves, UnorderedMap<RpoDigest, Word>) {
        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = UnorderedMap::new();

        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let mut leaf = self.get_leaf(&leaf_pairs[0].0);

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
                    leaf = self.construct_prospective_leaf(leaf, &key, &value);
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
        bottom_depth: u8,
        subtree: Option<Subtree>,
    ) -> (NodeMutations, SubtreeLeaf)
    where
        Self: Sized,
    {
        debug_assert!(bottom_depth <= tree_depth);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let subtree_root_depth = bottom_depth - SUBTREE_DEPTH;
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
                let parent_node = match subtree {
                    Some(ref subtree) => {
                        subtree.get_inner_node(parent_index).unwrap_or_else(|| {
                            EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                        })
                    },
                    None => self.get_inner_node(parent_index),
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

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index_val = Self::key_to_leaf_index(&key).value();

        match self
            .storage
            .get_leaf(leaf_index_val)
            .expect("Storage error during get_leaf in perform_insert")
        {
            Some(mut existing_leaf) => {
                let old_value = existing_leaf.get_value(&key);
                existing_leaf.insert(key, value);
                self.storage
                    .set_leaf(leaf_index_val, &existing_leaf)
                    .expect("Failed to store leaf during insert");
                old_value
            },
            None => {
                let new_leaf = SmtLeaf::Single((key, value));
                self.storage
                    .set_leaf(leaf_index_val, &new_leaf)
                    .expect("Failed to store new leaf during insert");
                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index_val = Self::key_to_leaf_index(&key).value();

        if let Some(mut leaf) = self
            .storage
            .get_leaf(leaf_index_val)
            .expect("Storage error during get_leaf in perform_remove")
        {
            let (old_value, is_empty) = leaf.remove(key); // SmtLeaf::remove returns Option<Word>
            if is_empty {
                self.storage.remove_leaf(leaf_index_val).expect("Failed to remove empty leaf");
            } else {
                self.storage
                    .set_leaf(leaf_index_val, &leaf)
                    .expect("Failed to store leaf during remove");
            }
            old_value
        } else {
            None
        }
    }

    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        for (index, node) in nodes {
            if index.depth() <= IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                self.in_memory_nodes[memory_index] = Some(node);
                self.in_memory_count += 1;
            }
        }
    }
}

impl<S: SmtStorage + 'static> SparseMerkleTree<SMT_DEPTH> for LargeSmt<S> {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: RpoDigest = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        _inner_nodes: InnerNodes,
        _leaves: Leaves,
        _root: RpoDigest,
    ) -> Result<Self, MerkleError> {
        // This method requires specific storage creation logic (e.g., a path for RocksDB)
        // which cannot be determined generically from the trait signature.
        // Use a specialized constructor or method on a concrete LargeSmt<StorageType> instead.
        panic!(
            "Generic LargeSmt::from_raw_parts is not supported; requires storage configuration."
        );
    }

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
        self.storage.set_root(root).expect("Failed to set root");
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() <= IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            return self.in_memory_nodes[memory_index]
                .clone()
                .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()));
        }

        self.storage
            .get_inner_node(index)
            .expect("Failed to get inner node")
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            let old = self.in_memory_nodes.get_mut(i).and_then(|slot| slot.take());
            if old.is_some() {
                self.in_memory_count -= 1;
            }
            return old;
        }
        self.storage
            .set_inner_node(index, inner_node)
            .expect("Failed to store inner node")
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            let old = self.in_memory_nodes.get_mut(memory_index).and_then(|slot| slot.take());
            if old.is_some() {
                self.in_memory_count -= 1;
            }
            return old;
        }
        self.storage.remove_inner_node(index).expect("Failed to remove inner node")
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Self::Value {
        let old_value = self.insert_value(key, value).unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return value;
        }

        let leaf = self.get_leaf(&key);
        let node_index = {
            let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);
            leaf_index.into()
        };

        self.recompute_nodes_from_index_to_root(node_index, Self::hash_leaf(&leaf));

        old_value
    }

    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        if value != Self::EMPTY_VALUE {
            self.perform_insert(key, value)
        } else {
            self.perform_remove(key)
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);
        match self.storage.get_leaf(leaf_pos.value()) {
            Ok(Some(leaf)) => leaf.get_value(key).unwrap_or_default(),
            Ok(None) => EMPTY_WORD,
            Err(e) => {
                panic!("Storage error during get_leaf in get_value: {:?}", e);
            },
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();
        match self.storage.get_leaf(leaf_pos) {
            Ok(Some(leaf)) => leaf,
            Ok(None) => SmtLeaf::new_empty(key.into()),
            Err(e) => {
                panic!("Storage error during get_leaf in get_leaf: {:?}", e);
            },
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        mut existing_leaf: SmtLeaf,
        key: &RpoDigest,
        value: &Word,
    ) -> SmtLeaf {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => SmtLeaf::new_single(*key, *value),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value);
                } else {
                    existing_leaf.remove(*key);
                }

                existing_leaf
            },
        }
    }

    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf = self.get_leaf(key);

        let mut idx: NodeIndex = LeafIndex::from(key).into();

        let mut cursor = idx.parent();
        let mut roots_indices = Vec::with_capacity(5);
        for _ in 0..5 {
            let root = Subtree::find_subtree_root(cursor);
            roots_indices.push(root);
            cursor = root.parent();
        }

        let subtrees_data =
            self.storage.get_subtrees(&roots_indices).expect("Failed to get subtrees");

        // cache subtrees in memory
        let mut cache = UnorderedMap::default();
        for (root, res) in roots_indices.into_iter().zip(subtrees_data.into_iter()) {
            let subtree = match res {
                Some(subtree_content) => subtree_content,
                None => panic!("There should be a subtree for root {:?} during open()", root),
            };
            cache.insert(root, subtree);
        }

        let mut path = Vec::with_capacity(idx.depth() as usize);
        while idx.depth() > 0 {
            let is_right = idx.is_value_odd();
            idx = idx.parent();

            let sibling_hash = if idx.depth() <= IN_MEMORY_DEPTH {
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

        let merkle_path = MerklePath::new(path);
        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    fn recompute_nodes_from_index_to_root(
        &mut self,
        mut index: NodeIndex,
        node_hash_at_index: RpoDigest,
    ) {
        let mut node_hash = node_hash_at_index;
        for node_depth in (0..index.depth()).rev() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Rpo256::merge(&[left, right]);

            if node_hash == *EmptySubtreeRoots::entry(SMT_DEPTH, node_depth) {
                // If a subtree is empty, then can remove the inner node, since it's equal to the
                // default value
                self.remove_inner_node(index);
            } else {
                self.insert_inner_node(index, InnerNode { left, right });
            }
        }
        self.set_root(node_hash);
    }

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl<S: SmtStorage + 'static> PartialEq for LargeSmt<S> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.num_leaves() == other.num_leaves()
            && self.num_entries() == other.num_entries()
    }
}

impl<S: SmtStorage + 'static> Eq for LargeSmt<S> {}

fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() <= IN_MEMORY_DEPTH);
    debug_assert!(index.value() < (1 << index.depth()));
    ((1usize << index.depth()) - 1) + index.value() as usize
}

#[allow(dead_code)]
fn flat_idx_to_node_index(flat_idx: usize) -> NodeIndex {
    let depth = (flat_idx + 1).ilog2() as u8;
    let nodes_before_this_depth = (1usize << depth) - 1;
    let value_at_depth = (flat_idx - nodes_before_this_depth) as u64;
    NodeIndex::new_unchecked(depth, value_at_depth)
}

impl<S: SmtStorage + 'static> Clone for LargeSmt<S> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            storage: Arc::clone(&self.storage),
            in_memory_nodes: self.in_memory_nodes.clone(),
            in_memory_count: self.in_memory_count,
        }
    }
}

// ITERATORS
// ================================================================================================

enum InnerNodeIteratorState<'a> {
    InMemory {
        current_index: usize,
        large_smt_in_memory_nodes: &'a Vec<Option<InnerNode>>,
    },
    Subtree {
        subtree_iter: Box<dyn Iterator<Item = Subtree> + 'a>,
        current_subtree_node_iter: Option<Box<dyn Iterator<Item = InnerNodeInfo> + 'a>>,
    },
    Done,
}

pub struct LargeSmtInnerNodeIterator<'a, S: SmtStorage + 'static> {
    large_smt: &'a LargeSmt<S>,
    state: InnerNodeIteratorState<'a>,
}

impl<'a, S: SmtStorage + 'static> LargeSmtInnerNodeIterator<'a, S> {
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

impl<S: SmtStorage + 'static> Iterator for LargeSmtInnerNodeIterator<'_, S> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
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

                    // If we exit the loop, all in-memory nodes (flat vector) have been processed.
                    // Transition to Subtree state.
                    match self.large_smt.storage.iter_subtrees() {
                        Ok(subtree_iter) => {
                            self.state = InnerNodeIteratorState::Subtree {
                                subtree_iter,
                                current_subtree_node_iter: None,
                            };
                            // Loop again to start processing subtrees immediately.
                            continue;
                        },
                        Err(_e) => {
                            self.state = InnerNodeIteratorState::Done;
                            return None; // No more items if subtree iterator fails.
                        },
                    }
                },
                InnerNodeIteratorState::Subtree { subtree_iter, current_subtree_node_iter } => {
                    loop {
                        if let Some(node_iter) = current_subtree_node_iter {
                            if let Some(info) = node_iter.as_mut().next() {
                                return Some(info);
                            }
                        }

                        match subtree_iter.next() {
                            Some(next_subtree) => {
                                let infos: Vec<InnerNodeInfo> =
                                    next_subtree.iter_inner_node_info().collect();
                                *current_subtree_node_iter = Some(Box::new(infos.into_iter()));
                            },
                            None => {
                                self.state = InnerNodeIteratorState::Done;
                                return None; // All done.
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
