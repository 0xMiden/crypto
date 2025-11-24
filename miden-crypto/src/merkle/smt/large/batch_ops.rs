use alloc::vec::Vec;
use core::mem;

use num::Integer;
use rayon::prelude::*;

use super::{
    IN_MEMORY_DEPTH, LargeSmt, LargeSmtError, LoadedLeaves, MutatedLeaves, SMT_DEPTH, SmtStorage,
    StorageUpdates, Subtree, SubtreeUpdate,
};
use crate::{
    Word,
    merkle::smt::{
        EmptySubtreeRoots, LeafIndex, Map, MerkleError, MutationSet, NodeIndex, NodeMutation,
        NodeMutations, SmtLeaf, SparseMerkleTree,
        full::concurrent::{
            SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter, fetch_sibling_pair,
            process_sorted_pairs_to_leaves,
        },
    },
};

// TYPES
// ================================================================================================

/// Prepared mutations loaded from storage, ready to be applied.
struct PreparedMutations {
    old_root: Word,
    new_root: Word,
    sorted_node_mutations: Vec<(NodeIndex, NodeMutation)>,
    loaded_subtrees: Map<NodeIndex, Option<Subtree>>,
    new_pairs: Map<Word, Word>,
    leaf_map: Map<u64, Option<SmtLeaf>>,
}

// BATCH OPERATIONS
// ================================================================================================

impl<S: SmtStorage> LargeSmt<S> {
    /// Processes one set of `subtree_leaves` at a given `subtree_root_depth` and returns:
    /// - node mutations to apply to in-memory nodes (empty if handled in subtree),
    /// - the computed subtree root leaf, and
    /// - a storage update instruction for the subtree.
    fn process_subtree_for_depth(
        &self,
        subtree_leaves: Vec<SubtreeLeaf>,
        subtree_root_depth: u8,
    ) -> (NodeMutations, SubtreeLeaf, SubtreeUpdate) {
        debug_assert!(subtree_leaves.is_sorted() && !subtree_leaves.is_empty());

        let subtree_root_index =
            NodeIndex::new_unchecked(subtree_root_depth, subtree_leaves[0].col >> SUBTREE_DEPTH);

        // Load subtree from storage if below in-memory horizon; otherwise use in-memory nodes
        let mut subtree_opt = if subtree_root_depth < IN_MEMORY_DEPTH {
            None
        } else {
            Some(
                self.storage
                    .get_subtree(subtree_root_index)
                    .expect("Storage error getting subtree in insert_batch")
                    .unwrap_or_else(|| Subtree::new(subtree_root_index)),
            )
        };

        // Build mutations for the subtree
        let (mutations, root) = self.build_subtree_mutations(
            subtree_leaves,
            SMT_DEPTH,
            subtree_root_depth,
            subtree_opt.as_ref(),
        );

        let (in_memory_mutations, subtree_update) = if subtree_root_depth < IN_MEMORY_DEPTH {
            // In-memory nodes: return mutations for direct application
            (mutations, SubtreeUpdate::None)
        } else {
            // Storage nodes: apply mutations to loaded subtree and determine storage action
            let modified = !mutations.is_empty();
            if let Some(subtree) = subtree_opt.as_mut() {
                for (index, mutation) in mutations {
                    match mutation {
                        NodeMutation::Removal => {
                            subtree.remove_inner_node(index);
                        },
                        NodeMutation::Addition(node) => {
                            subtree.insert_inner_node(index, node);
                        },
                    }
                }
            }

            let update = if !modified {
                SubtreeUpdate::None
            } else if let Some(subtree) = subtree_opt
                && !subtree.is_empty()
            {
                SubtreeUpdate::Store { index: subtree_root_index, subtree }
            } else {
                SubtreeUpdate::Delete { index: subtree_root_index }
            };

            (NodeMutations::default(), update)
        };

        (in_memory_mutations, root, subtree_update)
    }

    /// Helper function to load leaves from storage for a set of key-value pairs.
    /// Returns the deduplicated leaf indices and a map of loaded leaves.
    fn load_leaves_for_pairs(
        &self,
        sorted_kv_pairs: &[(Word, Word)],
    ) -> Result<LoadedLeaves, LargeSmtError> {
        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| Self::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.dedup();
        leaf_indices.par_sort_unstable();

        // Get leaves from storage
        let leaves_from_storage = self.storage.get_leaves(&leaf_indices)?;

        // Map leaf indices to their corresponding leaves
        let leaf_map: Map<u64, Option<SmtLeaf>> = leaf_indices
            .iter()
            .zip(leaves_from_storage)
            .map(|(index, maybe_leaf)| (*index, maybe_leaf))
            .collect();

        Ok((leaf_indices, leaf_map))
    }

    /// Computes leaves from a set of key-value pairs and current leaf values.
    ///
    /// Returns: (leaves for tree building, map of mutated leaf nodes, changed key-value pairs,
    /// leaf_delta, entry_delta)
    fn sorted_pairs_to_mutated_leaves_with_preloaded_leaves(
        &self,
        pairs: Vec<(Word, Word)>,
        leaf_map: &Map<u64, Option<SmtLeaf>>,
    ) -> MutatedLeaves {
        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = Map::new();
        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let leaf_index = LeafIndex::<SMT_DEPTH>::from(leaf_pairs[0].0);
            let old_leaf_opt = leaf_map.get(&leaf_index.value()).and_then(|opt| opt.as_ref());
            let old_entry_count = old_leaf_opt.map(|leaf| leaf.entries().len()).unwrap_or(0);

            let mut leaf = old_leaf_opt
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
                // Calculate deltas
                let new_entry_count = leaf.entries().len();

                match (&leaf, old_leaf_opt) {
                    (SmtLeaf::Empty(_), Some(_)) => {
                        // Leaf was deleted
                        leaf_count_delta -= 1;
                        entry_count_delta -= old_entry_count as isize;
                    },
                    (SmtLeaf::Empty(_), None) => {
                        // Was empty, still empty (shouldn't happen with leaf_changed=true)
                        unreachable!("Leaf was empty, but leaf_changed=true");
                    },
                    (_, None) => {
                        // New leaf created
                        leaf_count_delta += 1;
                        entry_count_delta += new_entry_count as isize;
                    },
                    (_, Some(_)) => {
                        // Leaf updated (not empty)
                        entry_count_delta += new_entry_count as isize - old_entry_count as isize;
                    },
                }

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
        let accumulator = accumulator.expect("process_sorted_pairs_to_leaves never fails");
        (
            accumulator.leaves,
            accumulator.nodes,
            new_pairs,
            leaf_count_delta,
            entry_count_delta,
        )
    }

    /// Computes the node mutations and the root of a subtree
    fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        tree_depth: u8,
        subtree_root_depth: u8,
        subtree: Option<&Subtree>,
    ) -> (NodeMutations, SubtreeLeaf) {
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
                let parent_node = if let Some(sub) = subtree {
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

    /// Inserts multiple key-value pairs into the tree in a single batch operation.
    ///
    /// This is the recommended method for bulk insertions, updates, and deletions. It efficiently
    /// processes all changes by loading each subtree and leaf only once, applying all mutations
    /// in-place, and leveraging parallel hashing throughout.
    ///
    /// To delete entries, pass [`EMPTY_WORD`](crate::EMPTY_WORD) as the value.
    ///
    /// # Returns
    /// Returns the new root hash of the tree after applying all changes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any leaf would exceed [`MAX_LEAF_ENTRIES`](crate::merkle::smt::MAX_LEAF_ENTRIES) (1024
    ///   entries)
    /// - Storage operations fail
    ///
    /// # Example
    /// ```no_run
    /// use miden_crypto::{
    ///     EMPTY_WORD, Felt, Word,
    ///     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
    /// };
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
    /// let mut smt = LargeSmt::new(storage)?;
    ///
    /// let entries = vec![
    ///     // Insert new entries
    ///     (
    ///         Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
    ///         Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
    ///     ),
    ///     (
    ///         Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]),
    ///         Word::new([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]),
    ///     ),
    ///     // Delete an entry
    ///     (Word::new([Felt::new(3), Felt::new(0), Felt::new(0), Felt::new(0)]), EMPTY_WORD),
    /// ];
    ///
    /// let new_root = smt.insert_batch(entries)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_batch(
        &mut self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Word, LargeSmtError>
    where
        Self: Sized + Sync,
    {
        // Sort key-value pairs by leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Load leaves from storage
        let (_leaf_indices, leaf_map) = self.load_leaves_for_pairs(&sorted_kv_pairs)?;

        // Process leaves in parallel to get mutated leaves for tree building AND deltas
        let (mut leaves, mutated_leaf_nodes, _new_pairs, leaf_count_delta, entry_count_delta) =
            self.sorted_pairs_to_mutated_leaves_with_preloaded_leaves(sorted_kv_pairs, &leaf_map);

        // Early return if no mutations
        let old_root = self.root()?;
        if leaves.is_empty() {
            return Ok(old_root);
        }

        let mut loaded_subtrees: Map<NodeIndex, Option<Subtree>> = Map::new();

        // Process each depth level in reverse, stepping by the subtree depth
        for subtree_root_depth in
            (0..=SMT_DEPTH - SUBTREE_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            // Build mutations and apply them to loaded subtrees
            let subtree_count = leaves.len();
            let is_in_memory = subtree_root_depth < IN_MEMORY_DEPTH;
            let mutations_capacity = if is_in_memory {
                subtree_count * SUBTREE_DEPTH as usize
            } else {
                0
            };
            let updates_capacity = if is_in_memory { 0 } else { subtree_count };

            let (in_memory_mutations, mut subtree_roots, modified_subtrees) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    self.process_subtree_for_depth(subtree_leaves, subtree_root_depth)
                })
                .fold(
                    || {
                        (
                            Vec::with_capacity(mutations_capacity),
                            Vec::with_capacity(subtree_count),
                            Vec::with_capacity(updates_capacity),
                        )
                    },
                    |(mut muts, mut roots, mut subtrees), (mem_muts, root, subtree_update)| {
                        muts.extend(mem_muts);
                        roots.push(root);
                        if !matches!(subtree_update, SubtreeUpdate::None) {
                            subtrees.push(subtree_update);
                        }
                        (muts, roots, subtrees)
                    },
                )
                .reduce(
                    || (Vec::new(), Vec::new(), Vec::new()),
                    |(mut m1, mut r1, mut s1), (m2, r2, s2)| {
                        m1.extend(m2);
                        r1.extend(r2);
                        s1.extend(s2);
                        (m1, r1, s1)
                    },
                );

            // Apply in-memory mutations
            for (index, mutation) in in_memory_mutations {
                match mutation {
                    NodeMutation::Removal => self.remove_inner_node(index),
                    NodeMutation::Addition(node) => self.insert_inner_node(index, node),
                };
            }

            // Convert SubtreeUpdate to storage format
            for update in modified_subtrees {
                match update {
                    SubtreeUpdate::None => {},
                    SubtreeUpdate::Store { index, subtree } => {
                        loaded_subtrees.insert(index, Some(subtree));
                    },
                    SubtreeUpdate::Delete { index } => {
                        loaded_subtrees.insert(index, None);
                    },
                }
            }

            // Prepare leaves for the next depth level
            leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            debug_assert!(!leaves.is_empty());
        }

        let new_root = leaves[0][0].hash;

        // Build leaf updates for storage (convert Empty to None for deletion)
        let mut leaf_update_map = leaf_map;

        for (idx, mutated_leaf) in mutated_leaf_nodes {
            let leaf_opt = match mutated_leaf {
                // Delete from storage
                SmtLeaf::Empty(_) => None,
                _ => Some(mutated_leaf),
            };
            leaf_update_map.insert(idx, leaf_opt);
        }

        // Atomic update to storage
        let updates = StorageUpdates::from_parts(
            leaf_update_map,
            loaded_subtrees,
            new_root,
            leaf_count_delta,
            entry_count_delta,
        );
        self.storage.apply(updates)?;

        Ok(new_root)
    }

    /// Prepares mutations by loading necessary data from storage.
    fn prepare_mutations(
        &self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<PreparedMutations, LargeSmtError> {
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        let expected_root = SparseMerkleTree::<SMT_DEPTH>::root(self);
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
        let loaded_subtrees: Map<NodeIndex, Option<Subtree>> = subtree_roots_indices
            .into_iter()
            .zip(subtrees_from_storage)
            .map(|(root_index, subtree_opt)| {
                (root_index, Some(subtree_opt.unwrap_or_else(|| Subtree::new(root_index))))
            })
            .collect();

        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = new_pairs.iter().map(|(k, v)| (*k, *v)).collect();
        sorted_kv_pairs.par_sort_by_key(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value());

        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.par_sort_unstable();
        leaf_indices.dedup();

        // Get leaves from storage
        let leaves = self.storage.get_leaves(&leaf_indices)?;

        // Map leaf indices to their corresponding leaves
        let leaf_map: Map<u64, Option<SmtLeaf>> = leaf_indices.into_iter().zip(leaves).collect();

        Ok(PreparedMutations {
            old_root,
            new_root,
            sorted_node_mutations: sorted_mutations,
            loaded_subtrees,
            new_pairs,
            leaf_map,
        })
    }

    /// Applies prepared mutations to the tree, updating storage.
    fn apply_prepared_mutations(
        &mut self,
        prepared: PreparedMutations,
    ) -> Result<(), LargeSmtError> {
        use NodeMutation::*;

        let PreparedMutations {
            old_root: _,
            new_root,
            sorted_node_mutations,
            mut loaded_subtrees,
            new_pairs,
            mut leaf_map,
        } = prepared;

        // Process node mutations
        for (index, mutation) in sorted_node_mutations {
            if index.depth() < IN_MEMORY_DEPTH {
                match mutation {
                    Removal => {
                        SparseMerkleTree::<SMT_DEPTH>::remove_inner_node(self, index);
                    },
                    Addition(node) => {
                        SparseMerkleTree::<SMT_DEPTH>::insert_inner_node(self, index, node);
                    },
                };
            } else {
                let subtree_root_index = Subtree::find_subtree_root(index);
                let subtree = loaded_subtrees
                    .get_mut(&subtree_root_index)
                    .expect("Subtree map entry must exist")
                    .as_mut()
                    .expect("Subtree must exist as it was either fetched or created");

                match mutation {
                    Removal => {
                        subtree.remove_inner_node(index);
                    },
                    Addition(node) => {
                        subtree.insert_inner_node(index, node);
                    },
                };
            }
        }

        // Go through subtrees, see if any are empty, and if so remove them
        for (_index, subtree) in loaded_subtrees.iter_mut() {
            if subtree.as_ref().is_some_and(|s| s.is_empty()) {
                *subtree = None;
            }
        }

        // Process leaf mutations
        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        for (key, value) in new_pairs {
            let idx = LargeSmt::<S>::key_to_leaf_index(&key).value();
            let entry = leaf_map.entry(idx).or_insert(None);

            // New value is empty, handle deletion
            if value == LargeSmt::<S>::EMPTY_VALUE {
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

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`LargeSmt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{Felt, Word};
    /// # use miden_crypto::merkle::{EmptySubtreeRoots, smt::{LargeSmt, MemoryStorage, SMT_DEPTH}};
    /// let mut smt = LargeSmt::new(MemoryStorage::new()).unwrap();
    /// let pair = (Word::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]).expect("compute_mutations ok");
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root().unwrap(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
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
        sorted_kv_pairs
            .par_sort_unstable_by_key(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value());

        // Load leaves from storage using helper
        let (_leaf_indices, leaf_map) = self.load_leaves_for_pairs(&sorted_kv_pairs)?;

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut leaves, _mutated_leaf_nodes, new_pairs, _leaf_count_delta, _entry_count_delta) =
            self.sorted_pairs_to_mutated_leaves_with_preloaded_leaves(sorted_kv_pairs, &leaf_map);

        // If no mutations, return an empty mutation set
        let old_root = SparseMerkleTree::<SMT_DEPTH>::root(self);
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
                    let subtree_opt = if subtree_root_depth < IN_MEMORY_DEPTH {
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
                        subtree_opt.as_ref(),
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
            old_root: SparseMerkleTree::<SMT_DEPTH>::root(self),
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

    /// Applies the prospective mutations computed with [`LargeSmt::compute_mutations()`] to this
    /// tree.
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
        let prepared = self.prepare_mutations(mutations)?;
        self.apply_prepared_mutations(prepared)?;
        Ok(())
    }

    /// Applies the prospective mutations computed with [`LargeSmt::compute_mutations()`] to this
    /// tree and returns the reverse mutation set.
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
        use NodeMutation::*;

        let prepared = self.prepare_mutations(mutations)?;
        let (old_root, new_root) = (prepared.old_root, prepared.new_root);

        // Collect reverse mutations: for each mutation, capture the old node state
        let reverse_mutations: NodeMutations = prepared
            .sorted_node_mutations
            .iter()
            .filter_map(|(index, mutation)| {
                let old_node = if index.depth() < IN_MEMORY_DEPTH {
                    self.get_non_empty_inner_node(*index)
                } else {
                    let subtree_root = Subtree::find_subtree_root(*index);
                    prepared
                        .loaded_subtrees
                        .get(&subtree_root)
                        .and_then(|opt| opt.as_ref())
                        .and_then(|subtree| subtree.get_inner_node(*index))
                };

                // Map (index, mutation, old_node) to the reverse mutation
                match (mutation, old_node) {
                    (Removal, Some(node)) => Some((*index, Addition(node))),
                    (Addition(_), Some(node)) => Some((*index, Addition(node))),
                    (Addition(_), None) => Some((*index, Removal)),
                    (Removal, None) => None,
                }
            })
            .collect();

        // Collect reverse pairs: for each key, capture the old value
        let reverse_pairs: Map<Word, Word> = prepared
            .new_pairs
            .keys()
            .map(|key| {
                let leaf_idx = LargeSmt::<S>::key_to_leaf_index(key).value();
                let old_value = prepared
                    .leaf_map
                    .get(&leaf_idx)
                    .and_then(|opt| opt.as_ref())
                    .and_then(|leaf| leaf.get_value(key))
                    .unwrap_or(LargeSmt::<S>::EMPTY_VALUE);
                (*key, old_value)
            })
            .collect();

        // Apply the mutations
        self.apply_prepared_mutations(prepared)?;

        Ok(MutationSet {
            old_root: new_root,
            node_mutations: reverse_mutations,
            new_pairs: reverse_pairs,
            new_root: old_root,
        })
    }
}
