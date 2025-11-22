use alloc::vec::Vec;
use core::mem;

use rayon::prelude::*;

use super::{
    CONSTRUCTION_SUBTREE_BATCH_SIZE, IN_MEMORY_DEPTH, LargeSmt, LargeSmtError, NUM_IN_MEMORY_NODES,
    SMT_DEPTH, SmtStorage, StorageError, Subtree,
};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        EmptySubtreeRoots, InnerNode, MerkleError, NodeIndex, Rpo256,
        smt::{
            Map, Smt, SparseMerkleTree,
            full::concurrent::{
                PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter, build_subtree,
            },
            large::to_memory_index,
        },
    },
};

// CONSTRUCTION
// ================================================================================================

impl<S: SmtStorage> LargeSmt<S> {
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

        // Initialize in-memory nodes
        let mut in_memory_nodes: Vec<Word> = vec![EMPTY_WORD; NUM_IN_MEMORY_NODES];

        for depth in 0..IN_MEMORY_DEPTH {
            let child_empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, depth + 1);
            let start = 2 * (1 << depth);
            let end = 2 * (1 << (depth + 1));
            in_memory_nodes[start..end].fill(child_empty_hash);
        }

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
                    // Store left and right children in flat layout
                    in_memory_nodes[memory_index * 2] = node.left;
                    in_memory_nodes[memory_index * 2 + 1] = node.right;
                }
            }
        }

        // Check that the calculated root matches the root in storage
        // Root is at index 1, with children at indices 2 and 3
        let calculated_root = Rpo256::merge(&[in_memory_nodes[2], in_memory_nodes[3]]);
        assert_eq!(calculated_root, root, "Tree reconstruction failed - root mismatch");

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
            return Err(StorageError::Unsupported(
                "Cannot create SMT with non-empty storage".into(),
            )
            .into());
        }
        let mut tree = LargeSmt::new(storage)?;
        if entries.is_empty() {
            return Ok(tree);
        }
        tree.build_subtrees(entries)?;
        Ok(tree)
    }

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

    // Inserts batch of upper inner nodes
    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        for (index, node) in nodes {
            if index.depth() < IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                // Store in flat layout: left at 2*i, right at 2*i+1
                self.in_memory_nodes[memory_index * 2] = node.left;
                self.in_memory_nodes[memory_index * 2 + 1] = node.right;
            }
        }
    }
}
