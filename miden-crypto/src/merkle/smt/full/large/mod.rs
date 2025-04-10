use alloc::vec::Vec;
use core::mem;
use std::{fs, path::Path, sync::Arc};

use num::Integer;
use rayon::prelude::*;
use rocksdb::{DB, Options, WriteBatch};
use winter_utils::{Deserializable, Serializable};

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, Leaves,
    MerkleError, MerklePath, MutationSet, NodeIndex, RpoDigest, SMT_DEPTH, Smt, SmtLeaf, SmtProof,
    SparseMerkleTree, Word,
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
#[derive(Debug, Clone)]
pub struct LargeSmt {
    root: RpoDigest,
    db: Arc<DB>,
    in_memory_nodes: Vec<Option<InnerNode>>,
    in_memory_count: usize,
}

impl LargeSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Smt].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new(path: &Path) -> Self {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.set_max_open_files(64);
        opts.increase_parallelism(rayon::current_num_threads() as i32);

        // Disable WAL for speed (safe only if you're okay losing progress on crash)
        // Note: this is used during write:
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.disable_wal(true);

        let db = Arc::new(DB::open(&opts, path).expect("Failed to open db"));

        let num_nodes = (1 << (IN_MEMORY_DEPTH + 1)) - 1;
        let in_memory_nodes = vec![None; num_nodes];

        Self {
            root: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
            db,
            in_memory_nodes,
            in_memory_count: 0,
        }
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
        path: &Path,
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        let entries: Vec<(RpoDigest, Word)> = entries.into_iter().collect();

        if entries.is_empty() {
            return Ok(Self::default());
        }

        let mut tree = LargeSmt::new(path);
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
        // TODO: make this more efficient
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        iter.filter_map(Result::ok) // unwrap Ok values, skip errors
            .filter(|(key, _)| key.starts_with(b"L")) // filter only leaf keys
            .count()
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    pub fn num_entries(&self) -> usize {
        //self.entries().count()
        // TODO: implement, currently counts all leaves
        self.num_leaves()
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
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        /*self.leaves
        .iter()
        .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))*/
        // TODO: implement
        vec![].into_iter()
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    pub fn entries(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        //self.leaves().flat_map(|(_, leaf)| leaf.entries())
        // TODO: implement
        vec![].into_iter()
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        //self.inner_nodes.values().map(|e| InnerNodeInfo {
        //    value: e.hash(),
        //    left: e.left,
        //    right: e.right,
        //})
        // TODO: implement
        vec![].into_iter()
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
        let (mut subtree_leaves, new_pairs) =
            self.sorted_pairs_to_mutated_subtree_leaves(sorted_kv_pairs);

        // If no mutations, return an empty mutation set
        if subtree_leaves.is_empty() {
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
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted() && !subtree.is_empty());
                    self.build_subtree_mutations(subtree, SMT_DEPTH, depth)
                })
                .unzip();

            // Prepare leaves for the next depth level
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            // Aggregate all node mutations
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            debug_assert!(!subtree_leaves.is_empty());
        }

        let new_root = subtree_leaves[0][0].hash;

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

        for (index, mutation) in node_mutations {
                match mutation {
                    Removal => {
                        self.remove_inner_node(index);
                    },
                    Addition(node) => {
                        self.insert_inner_node(index, node);
                    },
                }
        }

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
        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;
        // If there are no leaves, we can return early
        if initial_leaves.is_empty() {
            return Ok(());
        }

        // Store the leaves in the database
        self.store_leaves_to_db_batch(&initial_leaves);

        if initial_leaves.is_empty() {
            return Ok(());
        }

        for current_depth in (IN_MEMORY_DEPTH + SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            let (subtrees, mut subtree_roots): (Vec<(Vec<u8>, Vec<u8>)>, Vec<SubtreeLeaf>) =
                leaf_subtrees
                    .into_par_iter()
                    .map(|subtree| {
                        debug_assert!(subtree.is_sorted());
                        debug_assert!(!subtree.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree, SMT_DEPTH, current_depth);
                        // TODO: optimize this
                        let subtree_root_index = NodeIndex::new(current_depth-SUBTREE_DEPTH, subtree_root.col).unwrap();
                        let mut subtree = Subtree::new(subtree_root_index);
                        for (index, node) in nodes {    
                            subtree.insert_inner_node(index, node);
                        }
                        let subtree_key = Subtree::subtree_key(subtree_root_index);
                        let subtree_value = subtree.to_vec();
                        ((subtree_key, subtree_value), subtree_root)
                    })
                    .unzip();
            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!leaf_subtrees.is_empty());

            let mut batch = WriteBatch::default();
            for (key, value) in subtrees {
                batch.put(key, value);
            }
            self.db.write(batch).expect("Failed to store subtree batch");
        }
        for current_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
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

            // Insert the inner nodes into the tree
            for subtree_nodes in nodes {
                self.insert_inner_nodes_batch(subtree_nodes.into_iter());
            }
        }
        self.root = self.get_inner_node(NodeIndex::root()).hash();
        Ok(())
    }

    // MUTATIONS
    // --------------------------------------------------------------------------------------------

    /// Computes leaves from a set of key-value pairs and current leaf values.
    /// Derived from `sorted_pairs_to_leaves`
    fn sorted_pairs_to_mutated_subtree_leaves(
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
                let parent_node = self.get_inner_node(parent_index);
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
    fn leaf_key(index: u64) -> Vec<u8> {
        let mut key = vec![b'L'];
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    fn inner_key(depth: u8, value: u64) -> Vec<u8> {
        let mut key = vec![b'I', depth];
        key.extend_from_slice(&value.to_be_bytes());
        key
    }

    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        match self.get_leaf_from_db(&leaf_index) {
            Some(mut leaf) => {
                leaf.insert(key, value);
                self.store_leaf_to_db(leaf_index, &leaf);
                Some(value)
            },
            None => {
                self.store_leaf_to_db(leaf_index, &SmtLeaf::Single((key, value)));
                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        if let Some(mut leaf) = self.get_leaf_from_db(&leaf_index) {
            let (old_value, is_empty) = leaf.remove(key);
            if is_empty {
                self.remove_leaf_from_db(leaf_index);
            } else {
                self.store_leaf_to_db(leaf_index, &leaf);
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }

    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        use rocksdb::WriteBatch;

        let mut batch = WriteBatch::default();

        for (index, node) in nodes {
            if index.depth() <= IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                self.in_memory_nodes[memory_index] = Some(node);
                self.in_memory_count += 1;
            } else {
                let key = Self::inner_key(index.depth(), index.value());
                let value = node.to_bytes();
                batch.put(key, value);
            }
        }

        self.db.write(batch).expect("Failed to write inner nodes batch to RocksDB");
    }

    fn get_leaf_from_db(&self, index: &LeafIndex<SMT_DEPTH>) -> Option<SmtLeaf> {
        let key = Self::leaf_key(index.value());
        self.db
            .get(key)
            .ok()
            .flatten()
            .and_then(|bytes| SmtLeaf::read_from_bytes(&bytes).ok())
    }

    fn store_leaf_to_db(&mut self, index: LeafIndex<SMT_DEPTH>, leaf: &SmtLeaf) -> Option<SmtLeaf> {
        let key = Self::leaf_key(index.value());
        let old_bytes = self.db.get(&key).ok().flatten();
        let value = leaf.to_bytes();
        self.db.put(key, value).expect("Failed to store leaf");

        // deserialize and return old value if it existed
        old_bytes
            .map(|bytes| SmtLeaf::read_from_bytes(&bytes).expect("failed to deserialize InnerNode"))
    }

    fn store_leaves_to_db_batch(&mut self, leaves: &Leaves) {
        let mut batch = WriteBatch::default();
        for (idx, leaf) in leaves {
            let key = Self::leaf_key(*idx);
            let value = leaf.to_bytes();
            batch.put(key, value);
        }
        self.db.write(batch).expect("Failed to write batch");
    }

    fn remove_leaf_from_db(&mut self, index: LeafIndex<SMT_DEPTH>) -> Option<SmtLeaf> {
        let key = Self::leaf_key(index.value());

        let old_value = self
            .db
            .get(&key)
            .ok()
            .flatten()
            .and_then(|bytes| SmtLeaf::read_from_bytes(&bytes).ok());

        if old_value.is_some() {
            self.db.delete(&key).ok()?;
        }

        old_value
    }
}

impl SparseMerkleTree<SMT_DEPTH> for LargeSmt {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: RpoDigest = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        inner_nodes: InnerNodes,
        leaves: Leaves,
        root: RpoDigest,
    ) -> Result<Self, MerkleError> {
        if cfg!(debug_assertions) {
            let root_node = inner_nodes.get(&NodeIndex::root()).unwrap();
            assert_eq!(root_node.hash(), root);
        }
        let path = Path::new("large_smt.db");
        fs::create_dir_all(path).expect("Failed to create database directory");
        let mut smt = Self::new(path);
        smt.insert_inner_nodes_batch(inner_nodes);
        smt.store_leaves_to_db_batch(&leaves);
        smt.set_root(root);

        Ok(smt)
    }

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() <= IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            return self.in_memory_nodes[memory_index]
                .clone()
                .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()));
        }

        let subtree_root_index = Subtree::find_subtree_root(index);
        let subtree_key = Subtree::subtree_key(subtree_root_index);
        
        let subtree = self.db.get(&subtree_key)
            .ok()
            .flatten()
            .map_or_else(
                || Subtree::new(subtree_root_index),
                |bytes| Subtree::from_vec(subtree_root_index, bytes).unwrap()
            );

        subtree.get_inner_node(index).unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth())).clone()
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            let old = self.in_memory_nodes[i].replace(inner_node.clone());
            if old.is_none() {
                self.in_memory_count += 1;
            }
            return old;
        }

        let subtree_root_index = Subtree::find_subtree_root(index);
        let subtree_key = Subtree::subtree_key(subtree_root_index);
        let mut subtree = match self.db.get(&subtree_key).ok().flatten() {
            Some(subtree_bytes) => Subtree::from_vec(subtree_root_index, subtree_bytes).unwrap(),
            None => Subtree::new(subtree_root_index),
        };
        
        let old_value = subtree.insert_inner_node(index, inner_node);
        self.db.put(&subtree_key, subtree.to_vec()).expect("failed to write to RocksDB");

        // deserialize and return old value if it existed
        old_value
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

        let subtree_root_index = Subtree::find_subtree_root(index);
        let subtree_key = Subtree::subtree_key(subtree_root_index);
        let mut subtree = match self.db.get(&subtree_key).ok().flatten() {
            Some(subtree_bytes) => Subtree::from_vec(subtree_root_index, subtree_bytes).unwrap(),
            None => return None, // nothing to remove, return None
        };
        
        let old_value = subtree.remove_inner_node(index);
        self.db.put(&subtree_key, subtree.to_vec()).expect("failed to write to RocksDB");
        old_value
        // TODO: remove the whole subtree if empty
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
        match self.get_leaf_from_db(&leaf_pos) {
            Some(leaf) => leaf.get_value(key).unwrap_or_default(),
            None => EMPTY_WORD,
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();
        let key_bytes = Self::leaf_key(leaf_pos);

        match self.db.get(&key_bytes) {
            Ok(Some(bytes)) => {
                SmtLeaf::read_from_bytes(&bytes).unwrap_or_else(|_| SmtLeaf::new_empty(key.into()))
            },
            _ => SmtLeaf::new_empty(key.into()),
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

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl PartialEq for LargeSmt {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.num_leaves() == other.num_leaves()
            && self.num_entries() == other.num_entries()
    }
}

impl Eq for LargeSmt {}

impl Default for LargeSmt {
    fn default() -> Self {
        let path = Path::new("large_smt.db");
        fs::create_dir_all(path).expect("Failed to create database directory");
        Self::new(path)
    }
}

fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() <= IN_MEMORY_DEPTH);
    debug_assert!(index.value() < (1 << index.depth()));
    ((1usize << index.depth()) - 1) + index.value() as usize
}
