//! This module contains the definition of the history for the large SMT forest.
//!
//! The history consists of a series of deltas from the current state of the tree, moving backward
//! in history away from that current state. These are intended to be used to service queries to the
//! older states of the tree by semantically applying them in sequence to query at an older state.
//!
//! It provides functionality for adding new states to the history, as well as for querying the
//! history at a given point in time (represented by a root).
//!
//! # Complexity
//!
//! Deltas in this structure are _cumulative_. To get the entire picture of an arbitrary node or
//! leaf at version `v` it may be necessary to check for changes in all versions between `v` and the
//! current tree state. This gives worst-case complexity `O(v)` when querying a node or leaf for the
//! version `v`.
//!
//! This is acceptable overhead as we assert that newer versions are far more likely to be queried
//! than older versions. Nevertheless, it may be improved in future using a sharing approach, but is
//! being left for now for the sake of simplicity.
//!
//! # Performance
//!
//! This structure operates entirely in memory, and is hence reasonably quick to query. As of the
//! current time, no detailed benchmarking has taken place for the history, but based on some basic
//! profiling the major time taken is in chasing pointers throughout memory due to the use of
//! [`HashMap`], but this is unavoidable in the current structure and may need to be revisited in
//! the future.

use core::fmt::Debug;
use std::{
    collections::{HashMap, VecDeque},
    mem,
};

use crate::{
    Word,
    merkle::{
        NodeIndex,
        smt::{
            LeafIndex, SMT_DEPTH,
            large_forest::error::history::{HistoryError, Result},
        },
    },
};

/// A compact leaf is a mapping from full word-length keys to word-length values, intended to be
/// stored in the leaves of an otherwise shallower merkle tree.
pub type CompactLeaf = HashMap<Word, Word>;

/// A collection of changes to arbitrary non-leaf nodes in a merkle tree.
///
/// Note that if in the version of the tree represented by these `NodeChanges` had the default value
/// at the node, this default value _must_ be made concrete in the map. Failure to do so will retain
/// a newer, non-default value for that node, and thus result in incorrect query results at this
/// point in the history.
pub type NodeChanges = HashMap<NodeIndex, Word>;

/// A collection of changes to arbitrary leaf nodes in a merkle tree.
///
/// This represents the state of the leaf wholesale, rather than as a delta from the newer version.
/// This massively simplifies querying leaves in the history.
///
/// Note that if in the version of the tree represented by these `LeafChanges` had the default value
/// at the leaf, this default value must be made concrete in the map. Failure to do so will retain a
/// newer, non-default value for that leaf, and thus result in incorrect query results at this point
/// in the history.
pub type LeafChanges = HashMap<LeafIndex<SMT_DEPTH>, CompactLeaf>;

/// A History contains a sequence of versions atop a given tree.
///
/// The versions are _cumulative_, meaning that querying the history must account for changes from
/// the current tree that take place in versions that are not the queried version or the current
/// tree.
#[derive(Clone, Debug)]
pub struct History {
    /// The maximum number of historical versions to be stored.
    max_count: usize,

    /// The deltas that make up the history for this tree.
    ///
    /// It will never contain more than `max_count` deltas, and is ordered with the oldest data at
    /// the lowest index.
    ///
    /// # Implementation Note
    ///
    /// As we are targeting small numbers of history items (e.g. 30), having a sequence with an
    /// allocated capacity equal to the small maximum number of items is perfectly sane. This will
    /// avoid costly reallocations in the fast path.
    ///
    /// We use a [`VecDeque`] instead of a [`Vec`] or [`alloc::collections::LinkedList`] as we
    /// estimate that the vast majority of removals will be the oldest entries as new ones are
    /// pushed. This means that we can optimize for those removals along with indexing performance,
    /// rather than optimizing for more rare removals from the middle of the sequence.
    deltas: VecDeque<Delta>,
}

impl History {
    /// Constructs a new history container, containing at most `max_count` historical versions for
    /// a tree.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn empty(max_count: usize) -> Self {
        let deltas = VecDeque::with_capacity(max_count);
        Self { max_count, deltas }
    }

    /// Gets the maximum number of versions that this history can store.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn max_versions(&self) -> usize {
        self.max_count
    }

    /// Gets the current number of versions in the history.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn num_versions(&self) -> usize {
        self.deltas.len()
    }

    /// Returns `true` if a new entry can be added without removing the oldest, and `false`
    /// otherwise.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    fn can_add_version_without_removal(&self) -> bool {
        self.num_versions() < self.max_versions()
    }

    /// Adds a version to the history with the provided `root` and represented by the changes from
    /// the current tree given in `nodes` and `leaves`.
    ///
    /// If adding this version would result in exceeding `self.max_count` historical versions, then
    /// the oldest of the versions is automatically removed and returned. If no version is pruned,
    /// the method returns [`None`].
    ///
    /// # Gotchas
    ///
    /// When constructing the `nodes` and `leaves`, keep in mind that those collections must contain
    /// entries for the **default value of a node or leaf** at any position where the tree was
    /// sparse in the state represented by `root`. If this is not done, incorrect values may be
    /// returned.
    ///
    /// This is necessary because the changes are the _reverse_ from what one might expect. Namely,
    /// the changes in a given version `v` must "_revert_" the changes made in the transition from
    /// version `v` to version `v + 1`.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    pub fn add_version(
        &mut self,
        root: Word,
        nodes: NodeChanges,
        leaves: LeafChanges,
    ) -> Option<Delta> {
        let ret_val = if !self.can_add_version_without_removal() {
            Some(self.deltas.pop_front()?)
        } else {
            None
        };

        self.deltas.push_back(Delta::new(root, nodes, leaves));

        ret_val
    }

    /// Gets the delta corresponding to the tree version `v` with the provided `root` that
    /// represents the changes in the transition from version `v` to version `v + 1`.
    ///
    /// In particular, the return value is the simple delta and does **not account for any
    /// cumulative state changes**. It should not be used alone as an overlay for the current tree.
    /// See [`History::view_at`] for querying the overlay state correctly.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if there is no state in the history that corresponds to
    ///   the provided root.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    pub fn get_version(&self, root: &Word) -> Result<&Delta> {
        self.deltas
            .iter()
            .find(|d| d.root == *root)
            .ok_or(HistoryError::NoSuchVersion(*root))
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay was reverting the tree to the state in
    /// the specified `root`.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if there is no state in the history that corresponds to
    ///   the provided root.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    pub fn view_at(&self, root: &Word) -> Result<HistoryView<'_>> {
        HistoryView::new(root, self)
    }

    /// Removes the version from the history that corresponds to the specified `root`.
    ///
    /// # Arbitrary Removal
    ///
    /// This function allows arbitrary removal of any version in the history. When removing some
    /// version `v` that is not the oldest, the changes represented by version `v` are combined with
    /// the changes already in version `v - 1`. This ensures that `v - 1` and any older versions
    /// remain correct deltas on the tree state.
    ///
    /// # Performance
    ///
    /// It is significantly more performant to remove the oldest version from the tree than it is to
    /// remove any other version. This is because the oldest version does not result in any versions
    /// being collapsed together.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if there is no state in the history that corresponds to
    ///   the provided `root`.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    pub fn remove_version(&mut self, root: &Word) -> Result<()> {
        if let Some(ix) = self.deltas.iter().position(|d| d.root == *root) {
            if ix == 0 {
                self.remove_oldest_version()
            } else {
                // Start by removing the delta that has been specified, and also getting a handle to
                // the delta in the history that is one version older than the removed delta.
                let mut removed =
                    self.deltas.remove(ix).expect("Could not remove index known to be in bounds");
                let older = self
                    .deltas
                    .get_mut(ix - 1)
                    .expect("No older version available yet removed delta not at index 0");

                // We want to merge `removed` with `older`, but to do so we want to keep values from
                // `older` instead of `removed` when merging. This ensures that `older` remains a
                // coherent delta from the now 'next younger' state.
                //
                // We could `clone` but frankly a `memcpy` is going to be a lot faster than a new
                // allocation, so we swap `older` and `removed`, putting `removed` back in the queue
                // of deltas in place of older.
                mem::swap(older, &mut removed);

                // We then use the contents of `removed` (which now contains the OLDER) data, and
                // extend the data in the queue (which now contains the NEWER data, starting in the
                // state of what was previously in `removed`) in order to replace any clashes with
                // the OLDER overlay data.
                older.root = removed.root;
                older.nodes.extend(removed.nodes);
                older.leaves.extend(removed.leaves);

                Ok(())
            }
        } else {
            Err(HistoryError::NoSuchVersion(*root))
        }
    }

    /// Removes the oldest version from the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NothingToRemove`] if there are no versions in the history.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    pub fn remove_oldest_version(&mut self) -> Result<()> {
        if self.deltas.pop_front().is_some() {
            Ok(())
        } else {
            Err(HistoryError::NothingToRemove)
        }
    }
}

/// A read-only view of the history overlay on the tree at a specified place in the history.
///
/// # Construction
///
/// The type is only intended to be constructed by the [`History`] itself, and hence exposes no
/// public methods to construct it. If this needs to change, extreme caution must be taken to
/// maintain the internal invariants expected by the type.
///
/// If these invariants have not been met, the functions in the interface will return incorrect
/// results, but should not result in crashes at runtime.
#[derive(Debug)]
pub struct HistoryView<'history> {
    /// The index of the version with the provided `root` in the history.
    root_ix: usize,

    /// The history that actually stores the data that will be queried.
    history: &'history History,
}

impl<'history> HistoryView<'history> {
    /// Constructs a new history view that acts as a single overlay of the state represented by
    /// `root` in the provided `history` on the current tree.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if the requested `root` is not found in the history.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    fn new(root: &Word, history: &'history History) -> Result<Self> {
        if let Some(root_ix) = history.deltas.iter().position(|d| d.root == *root) {
            Ok(Self { root_ix, history })
        } else {
            Err(HistoryError::NoSuchVersion(*root))
        }
    }

    /// Gets the value of the node in the history at the provided `index`, or returns `None` if the
    /// version does not overlay the current tree at that node.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn node_value(&self, index: &NodeIndex) -> Option<&Word> {
        self.history.deltas.iter().skip(self.root_ix).find_map(|v| v.nodes.get(index))
    }

    /// Gets the value of the entire leaf in the history at the specified `index`, or returns `None`
    /// if the version does not overlay the current tree at that leaf.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn leaf_value(&self, index: &LeafIndex<SMT_DEPTH>) -> Option<&CompactLeaf> {
        self.history.deltas.iter().skip(self.root_ix).find_map(|v| v.leaves.get(index))
    }

    /// Queries the value of a specific key in a leaf in the overlay, returning:
    ///
    /// - `None` if the version does not overlay that leaf in the current tree,
    /// - `Some(None)` if the version does overlay that leaf but the compact leaf does not contain
    ///   that value,
    /// - and `Some(Some(v))` if the version does overlay the leaf and the key exists in that leaf.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn value(&self, key: &Word) -> Option<Option<&Word>> {
        self.leaf_value(&LeafIndex::from(*key)).map(|leaf| leaf.get(key))
    }
}

/// A delta for a state `n` represents the changes (to both nodes and leaves) that need to be
/// applied on top of the state `n + 1` to yield the correct tree for state `n`.
///
/// # Cumulative Deltas and Temporal Ordering
///
/// In order to best represent the history of a merkle tree, these deltas are constructed to take
/// advantage of two main properties:
///
/// - They are _cumulative_, which reduces their practical memory usage. This does, however, mean
///   that querying the state of older blocks is more expensive than querying newer ones.
/// - Deltas are applied in **temporally reversed order** from what one might expect. Most
///   conventional applications of deltas bring something from the past into the future through
///   application. In our case, the application of one or more deltas moves the tree into a **past
///   state**.
///
/// # Construction
///
/// While the [`Delta`] type is visible in the interface of the history, it is only intended to be
/// constructed by the history. Users should not be allowed to construct it directly.
#[derive(Clone, Debug, PartialEq)]
pub struct Delta {
    /// The root of the tree in the `version` corresponding to this delta.
    root: Word,

    /// Any changes to the non-leaf nodes in the tree for this delta.
    nodes: NodeChanges,

    /// Any changes to the leaf nodes in the tree for this delta.
    ///
    /// Note that the leaf state is **not represented compactly**, and describes the entire state
    /// of the leaf in the corresponding version.
    leaves: LeafChanges,
}

impl Delta {
    /// Creates a new delta with the provided `root`, and representing the provided
    /// changes to `nodes` and `leaves` in the merkle tree.
    #[must_use]
    fn new(root: Word, nodes: NodeChanges, leaves: LeafChanges) -> Self {
        Self { root, nodes, leaves }
    }

    /// Gets the root of the tree created by applying the delta.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn root(&self) -> Word {
        self.root
    }

    /// Gets the nodes that need to be altered in applying the delta.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn nodes(&self) -> &NodeChanges {
        &self.nodes
    }

    /// Gets the leaves that need to be altered in applying the delta.
    #[allow(dead_code)] // Temporary: this is internal code being merged incrementally
    #[must_use]
    pub fn leaves(&self) -> &LeafChanges {
        &self.leaves
    }
}

#[cfg(test)]
mod tests {
    use rand_utils::rand_value;

    use super::*;

    #[test]
    fn empty() {
        let history = History::empty(5);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 5);
        assert!(history.can_add_version_without_removal());
    }

    #[test]
    fn add_version() {
        // Prep our test data
        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        // Starting in an empty state we should be able to add deltas up until the limit we set.
        let mut history = History::empty(2);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 2);

        let root_1 = rand_value::<Word>();
        history.add_version(root_1, nodes.clone(), leaves.clone());
        assert_eq!(history.num_versions(), 1);
        assert!(history.can_add_version_without_removal());

        let root_2 = rand_value::<Word>();
        history.add_version(root_2, nodes.clone(), leaves.clone());
        assert_eq!(history.num_versions(), 2);
        assert!(!history.can_add_version_without_removal());

        // At this point, adding any new entry removes the oldest.
        let root_3 = rand_value::<Word>();
        history.add_version(root_3, nodes.clone(), leaves.clone());
        assert_eq!(history.num_versions(), 2);
        assert!(!history.can_add_version_without_removal());

        // This means that if we query for `root_1` it won't be there anymore.
        assert_eq!(history.get_version(&root_1), Err(HistoryError::NoSuchVersion(root_1)));

        // But `root_2` and `root_3` should.
        assert!(history.get_version(&root_2).is_ok());
        assert!(history.get_version(&root_3).is_ok());
    }

    #[test]
    fn remove_version() {
        // Starting in an empty state we should be able to add deltas up until the limit we set.
        let mut history = History::empty(3);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 3);

        // We can add an initial version with some changes in both nodes and leaves.
        let root_1 = rand_value::<Word>();

        let mut nodes_1 = NodeChanges::default();
        let n1_value: Word = rand_value();
        let n2_value: Word = rand_value();
        nodes_1.insert(NodeIndex::new(2, 1).unwrap(), n1_value);
        nodes_1.insert(NodeIndex::new(8, 128).unwrap(), n2_value);

        let mut leaf_1 = CompactLeaf::new();
        let l1_e1_key: Word = rand_value();
        let l1_e1_value: Word = rand_value();
        leaf_1.insert(l1_e1_key, l1_e1_value);

        let mut leaf_2 = CompactLeaf::new();
        let l2_e1_key: Word = rand_value();
        let l2_e1_value: Word = rand_value();
        let l2_e2_key: Word = rand_value();
        let l2_e2_value: Word = rand_value();
        leaf_2.insert(l2_e1_key, l2_e1_value);
        leaf_2.insert(l2_e2_key, l2_e2_value);

        let mut leaves_1 = LeafChanges::default();
        leaves_1.insert(LeafIndex::new(128).unwrap(), leaf_1.clone());
        leaves_1.insert(LeafIndex::new(256).unwrap(), leaf_2.clone());

        history.add_version(root_1, nodes_1.clone(), leaves_1.clone());
        assert_eq!(history.num_versions(), 1);
        assert!(history.can_add_version_without_removal());

        // We then add another version that overlaps with the older version.
        let root_2 = rand_value::<Word>();

        let mut nodes_2 = NodeChanges::default();
        let n3_value: Word = rand_value();
        let n4_value: Word = rand_value();
        nodes_2.insert(NodeIndex::new(2, 1).unwrap(), n3_value);
        nodes_2.insert(NodeIndex::new(10, 256).unwrap(), n4_value);

        let mut leaf_3 = CompactLeaf::new();
        let l3_e1_key: Word = rand_value();
        let l3_e1_value: Word = rand_value();
        leaf_3.insert(l3_e1_key, l3_e1_value);

        let mut leaves_2 = LeafChanges::default();
        leaves_2.insert(LeafIndex::new(256).unwrap(), leaf_3.clone());
        history.add_version(root_2, nodes_2.clone(), leaves_2.clone());
        assert_eq!(history.num_versions(), 2);
        assert!(history.can_add_version_without_removal());

        // And another version for the sake of argument.
        let root_3 = rand_value::<Word>();

        let mut nodes_3 = NodeChanges::default();
        let n5_value: Word = rand_value();
        nodes_3.insert(NodeIndex::new(30, 1).unwrap(), n5_value);

        let mut leaf_4 = CompactLeaf::new();
        let l4_e1_key: Word = rand_value();
        let l4_e1_value: Word = rand_value();
        leaf_4.insert(l4_e1_key, l4_e1_value);

        let mut leaves_3 = LeafChanges::default();
        leaves_3.insert(LeafIndex::new(256).unwrap(), leaf_4);

        history.add_version(root_3, nodes_3.clone(), leaves_3.clone());
        assert_eq!(history.num_versions(), 3);
        assert!(!history.can_add_version_without_removal());

        // When we remove a version in the middle of the history (root_2), its edits should get
        // collapsed with the next oldest version (root_1), favouring the older version, and the
        // removal should succeed.
        assert!(history.remove_version(&root_2).is_ok());
        assert_eq!(history.num_versions(), 2);
        assert!(history.can_add_version_without_removal());

        let oldest_version = history.get_version(&root_1);
        assert!(oldest_version.is_ok());
        let oldest_version = oldest_version.unwrap();

        assert_eq!(oldest_version.nodes.get(&NodeIndex::new(2, 1).unwrap()), Some(&n1_value));
        assert_eq!(oldest_version.nodes.get(&NodeIndex::new(8, 128).unwrap()), Some(&n2_value));
        assert_eq!(oldest_version.nodes.get(&NodeIndex::new(10, 256).unwrap()), Some(&n4_value));

        assert_eq!(oldest_version.leaves.get(&LeafIndex::new(128).unwrap()), Some(&leaf_1));
        assert_eq!(oldest_version.leaves.get(&LeafIndex::new(256).unwrap()), Some(&leaf_2));

        // The other entries should be untouched.
        let newest_version = history.get_version(&root_3);
        assert!(newest_version.is_ok());
        let newest_version = newest_version.unwrap();
        assert_eq!(newest_version.nodes, nodes_3);
        assert_eq!(newest_version.leaves, leaves_3);
    }

    #[test]
    fn remove_oldest_version() {
        // Prep our test data
        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        // Starting in an empty state we should be able to add deltas up until the limit we set.
        let mut history = History::empty(2);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 2);

        let root_1 = rand_value::<Word>();
        history.add_version(root_1, nodes.clone(), leaves.clone());
        assert_eq!(history.num_versions(), 1);
        assert!(history.can_add_version_without_removal());

        // With one version in it, we should be able to remove it.
        assert!(history.remove_oldest_version().is_ok());

        // But when there are no versions left removal should result in an error.
        assert_eq!(history.remove_oldest_version(), Err(HistoryError::NothingToRemove));
    }

    #[test]
    fn view_at() {
        // Starting in an empty state we should be able to add deltas up until the limit we set.
        let mut history = History::empty(3);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 3);

        // We can add an initial version with some changes in both nodes and leaves.
        let root_1 = rand_value::<Word>();

        let mut nodes_1 = NodeChanges::default();
        let n1_value: Word = rand_value();
        let n2_value: Word = rand_value();
        nodes_1.insert(NodeIndex::new(2, 1).unwrap(), n1_value);
        nodes_1.insert(NodeIndex::new(8, 128).unwrap(), n2_value);

        let mut leaf_1 = CompactLeaf::new();
        let l1_e1_key: Word = rand_value();
        let l1_e1_value: Word = rand_value();
        let leaf_1_ix = LeafIndex::from(l1_e1_key);
        leaf_1.insert(l1_e1_key, l1_e1_value);

        let mut leaf_2 = CompactLeaf::new();
        let l2_e1_key: Word = rand_value();
        let l2_e1_value: Word = rand_value();
        let leaf_2_ix = LeafIndex::from(l2_e1_key);
        let mut l2_e2_key: Word = rand_value();
        l2_e2_key[3] = leaf_2_ix.value().try_into().unwrap();
        let l2_e2_value: Word = rand_value();
        leaf_2.insert(l2_e1_key, l2_e1_value);
        leaf_2.insert(l2_e2_key, l2_e2_value);

        let mut leaves_1 = LeafChanges::default();
        leaves_1.insert(leaf_1_ix, leaf_1.clone());
        leaves_1.insert(leaf_2_ix, leaf_2.clone());

        history.add_version(root_1, nodes_1.clone(), leaves_1.clone());
        assert_eq!(history.num_versions(), 1);
        assert!(history.can_add_version_without_removal());

        // We then add another version that overlaps with the older version.
        let root_2 = rand_value::<Word>();

        let mut nodes_2 = NodeChanges::default();
        let n3_value: Word = rand_value();
        let n4_value: Word = rand_value();
        nodes_2.insert(NodeIndex::new(2, 1).unwrap(), n3_value);
        nodes_2.insert(NodeIndex::new(10, 256).unwrap(), n4_value);

        let mut leaf_3 = CompactLeaf::new();
        let leaf_3_ix = leaf_2_ix;
        let mut l3_e1_key: Word = rand_value();
        l3_e1_key[3] = leaf_3_ix.value().try_into().unwrap();
        let l3_e1_value: Word = rand_value();
        leaf_3.insert(l3_e1_key, l3_e1_value);

        let mut leaves_2 = LeafChanges::default();
        leaves_2.insert(leaf_3_ix, leaf_3.clone());
        history.add_version(root_2, nodes_2.clone(), leaves_2.clone());
        assert_eq!(history.num_versions(), 2);
        assert!(history.can_add_version_without_removal());

        // And another version for the sake of the test.
        let root_3 = rand_value::<Word>();

        let mut nodes_3 = NodeChanges::default();
        let n5_value: Word = rand_value();
        nodes_3.insert(NodeIndex::new(30, 1).unwrap(), n5_value);

        let mut leaf_4 = CompactLeaf::new();
        let l4_e1_key: Word = rand_value();
        let l4_e1_value: Word = rand_value();
        let leaf_4_ix = LeafIndex::from(l4_e1_key);
        leaf_4.insert(l4_e1_key, l4_e1_value);

        let mut leaves_3 = LeafChanges::default();
        leaves_3.insert(leaf_4_ix, leaf_4.clone());

        history.add_version(root_3, nodes_3.clone(), leaves_3.clone());
        assert_eq!(history.num_versions(), 3);
        assert!(!history.can_add_version_without_removal());

        // At this point, we can now grab a view into the history. This should error for an invalid
        // version.
        let invalid_root: Word = rand_value();
        let invalid_view = history.view_at(&invalid_root);
        assert!(invalid_view.is_err());
        assert_eq!(invalid_view.unwrap_err(), HistoryError::NoSuchVersion(invalid_root));

        // We should also be able to grab a view at a valid point in the history. We grab the oldest
        // possible version to ensure that the overlay logic functions correctly.
        let view = history.view_at(&root_1);
        assert!(view.is_ok());
        let view = view.unwrap();

        // Getting a node in the targeted version should just return it.
        assert_eq!(view.node_value(&NodeIndex::new(2, 1).unwrap()), Some(&n1_value));
        assert_eq!(view.node_value(&NodeIndex::new(8, 128).unwrap()), Some(&n2_value));

        // Getting a node that is _not_ in the targeted delta directly should search through the
        // versions in between the targeted version at the current tree and return the oldest value
        // it can find for it.
        assert_eq!(view.node_value(&NodeIndex::new(10, 256).unwrap()), Some(&n4_value));
        assert_eq!(view.node_value(&NodeIndex::new(30, 1).unwrap()), Some(&n5_value));

        // Getting a node that doesn't exist in ANY versions should return none.
        assert!(view.node_value(&NodeIndex::new(45, 100).unwrap()).is_none());

        // Similarly, getting a leaf from the targeted version should just return it.
        assert_eq!(view.leaf_value(&leaf_1_ix), Some(&leaf_1));
        assert_eq!(view.leaf_value(&leaf_2_ix), Some(&leaf_2));

        // But getting a leaf that is not in the target delta directly should result in the same
        // traversal.
        assert_eq!(view.leaf_value(&leaf_4_ix), Some(&leaf_4));

        // And getting a leaf that does not exist in any of the versions should return one.
        assert!(view.leaf_value(&LeafIndex::new(1024).unwrap()).is_none());

        // Finally, getting a full value from a compact leaf should yield the value directly from
        // the target version if the target version overlays it AND contains it.
        assert_eq!(view.value(&l1_e1_key), Some(Some(&l1_e1_value)));
        assert_eq!(view.value(&l2_e1_key), Some(Some(&l2_e1_value)));
        assert_eq!(view.value(&l2_e2_key), Some(Some(&l2_e2_value)));

        // However, if the leaf exists but does not contain the provided word, it should return the
        // sentinel `Some(None)`.
        let mut ne_key_in_existing_leaf: Word = rand_value();
        ne_key_in_existing_leaf[3] = leaf_1_ix.value().try_into().unwrap();
        assert_eq!(view.value(&ne_key_in_existing_leaf), Some(None));

        // If the leaf is not overlaid, then the lookup should go up the chain just as in the other
        // cases.
        assert_eq!(view.value(&l4_e1_key), Some(Some(&l4_e1_value)));

        // But if nothing is found, it should just return None;
        let ne_key: Word = rand_value();
        assert!(view.value(&ne_key).is_none());
    }
}
