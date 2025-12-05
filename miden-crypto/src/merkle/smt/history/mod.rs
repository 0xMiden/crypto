//! This module contains the definition of [`History`], a simple container for some number of
//! historical versions of a given merkle tree.
//!
//! This history consists of a series of _deltas_ from the current state of the tree, moving
//! backward in history away from that current state. These deltas are then used to form a "merged
//! overlay" that represents the changes to be made on top of the current tree to put it _back_ in
//! that historical state.
//!
//! It provides functionality for adding new states to the history, as well as for querying the
//! history at a given point in time.
//!
//! # Complexity
//!
//! Versions in this structure are _cumulative_. To get the entire picture of an arbitrary node or
//! leaf at version `v` it may be necessary to check for changes in all versions between `v` and the
//! current tree state. This gives worst-case complexity `O(v)` when querying a node or leaf for the
//! version `v`.
//!
//! This is acceptable overhead as we assert that newer versions are far more likely to be queried
//! than older versions. Nevertheless, it may be improved in future using a sharing approach, but
//! that potential improvement is being ignored for now for the sake of simplicity.
//!
//! # Performance
//!
//! This structure operates entirely in memory, and is hence reasonably quick to query. As of the
//! current time, no detailed benchmarking has taken place for the history, but based on some basic
//! profiling the major time taken is in chasing pointers throughout memory due to the use of
//! [`Map`]s, but this is unavoidable in the current structure and may need to be revisited in
//! the future.

pub mod error;

use alloc::collections::VecDeque;
use core::fmt::Debug;

use error::{HistoryError, Result};

use crate::{
    Map, Set, Word,
    merkle::{
        NodeIndex,
        smt::{LeafIndex, SMT_DEPTH},
    },
};

// UTILITY TYPE ALIASES
// ================================================================================================

/// A compact leaf is a mapping from full word-length keys to word-length values, intended to be
/// stored in the leaves of an otherwise shallower merkle tree.
pub type CompactLeaf = Map<Word, Word>;

/// A collection of changes to arbitrary non-leaf nodes in a merkle tree.
///
/// Note that if in the version of the tree represented by these `NodeChanges` had the default value
/// at the node, this default value _must_ be made concrete in the map. Failure to do so will retain
/// a newer, non-default value for that node, and thus result in incorrect query results at this
/// point in the history.
pub type NodeChanges = Map<NodeIndex, Word>;

/// A collection of changes to arbitrary leaf nodes in a merkle tree.
///
/// This represents the state of the leaf wholesale, rather than as a delta from the newer version.
/// This massively simplifies querying leaves in the history.
///
/// Note that if in the version of the tree represented by these `LeafChanges` had the default value
/// at the leaf, this default value must be made concrete in the map. Failure to do so will retain a
/// newer, non-default value for that leaf, and thus result in incorrect query results at this point
/// in the history.
pub type LeafChanges = Map<LeafIndex<SMT_DEPTH>, CompactLeaf>;

/// An identifier for a historical tree version overlay, which must be monotonic as new versions are
/// added.
pub type VersionId = u64;

// HISTORY
// ================================================================================================

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
    #[must_use]
    pub fn empty(max_count: usize) -> Self {
        let deltas = VecDeque::with_capacity(max_count);
        Self { max_count, deltas }
    }

    /// Gets the maximum number of versions that this history can store.
    #[must_use]
    pub fn max_versions(&self) -> usize {
        self.max_count
    }

    /// Gets the current number of versions in the history.
    #[must_use]
    pub fn num_versions(&self) -> usize {
        self.deltas.len()
    }

    /// Returns `true` if a new entry can be added without removing the oldest, and `false`
    /// otherwise.
    #[must_use]
    pub fn can_add_version_without_removal(&self) -> bool {
        self.num_versions() < self.max_versions()
    }

    /// Returns all the roots that the history knows about.
    ///
    /// # Complexity
    ///
    /// Calling this method requires a traversal of all the versions and is hence linear in the
    /// number of history versions.
    #[must_use]
    pub fn roots(&self) -> Set<Word> {
        self.deltas.iter().map(|d| d.root()).collect()
    }

    /// Returns `true` if `root` is in the history and `false` otherwise.
    ///
    /// # Complexity
    ///
    /// Calling this method requires a traversal of all the versions and is hence linear in the
    /// number of history versions.
    #[must_use]
    pub fn knows_root(&self, root: Word) -> bool {
        self.deltas.iter().any(|r| r.root == root)
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
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NonMonotonicVersions`] if the provided version is not greater than the
    ///   previously added version.
    pub fn add_version(
        &mut self,
        root: Word,
        version_id: VersionId,
        nodes: NodeChanges,
        leaves: LeafChanges,
    ) -> Result<Option<Delta>> {
        if let Some(v) = self.deltas.iter().last() {
            if v.version_id < version_id {
                let ret_val = if !self.can_add_version_without_removal() {
                    self.deltas.pop_front()
                } else {
                    None
                };

                self.deltas.push_back(Delta::new(root, version_id, nodes, leaves));

                Ok(ret_val)
            } else {
                Err(HistoryError::NonMonotonicVersions(version_id, v.version_id))
            }
        } else {
            self.deltas.push_back(Delta::new(root, version_id, nodes, leaves));

            Ok(None)
        }
    }

    /// Gets the first version corresponding to the oldest tree version `v` for which the provided
    /// `f` returns `true`.
    ///
    /// This version represents the transition from version `v` to version `v + 1`, and is a simple
    /// delta that **does not account for any cumulative state changes**. It should not be used
    /// alone as an overlay for the current tree. See [`History::view_at`] and friends for querying
    /// the overlay state correctly.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    pub fn get_version_by(&self, f: impl FnMut(&&Delta) -> bool) -> Result<&Delta> {
        self.deltas.iter().find(f).ok_or(HistoryError::NoSuchVersion)
    }

    /// Gets the version corresponding to the tree version `v` with the provided `root` that
    /// represents the changes in the transition from version `v` to version `v + 1`.
    ///
    /// In particular, the return value is the simple delta and does **not account for any
    /// cumulative state changes**. It should not be used alone as an overlay for the current tree.
    /// See [`History::view_at_root`] for querying the overlay state correctly.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchRoot`] if there is no state in the history that corresponds to the
    ///   provided root.
    pub fn get_version_by_root(&self, root: Word) -> Result<&Delta> {
        self.get_version_by(|d| d.root == root)
            .map_err(|_| HistoryError::NoSuchRoot(root))
    }

    /// Gets the version corresponding to the tree version `v` with the provided `version_id` that
    /// represents the changes made in the transition from version `v` to version `v + 1`.
    ///
    /// In particular, the return value is the simple delta and does **not account for any
    /// cumulative state changes**. It should not be used alone as an overlay for the current tree.
    /// See [`History::view_at_id`] for querying the overlay state correctly.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchId`] if there is no state in the history that corresponds to the
    ///   provided id.
    pub fn get_version_by_id(&self, version_id: VersionId) -> Result<&Delta> {
        self.get_version_by(|d| d.version_id == version_id)
            .map_err(|_| HistoryError::NoSuchId(version_id))
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay reverts the tree to the state given by
    /// the oldest version for which `f` returns true.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if `f` does not return `true` for any versions in the
    ///   history.
    pub fn view_at(&self, f: impl FnMut(&Delta) -> bool) -> Result<HistoryView<'_>> {
        HistoryView::new_of(f, self)
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay was reverting the tree to the state in
    /// the specified `root`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchRoot`] if there is no state in the history that corresponds to the
    ///   provided root.
    pub fn view_at_root(&self, root: Word) -> Result<HistoryView<'_>> {
        self.view_at(|d| d.root == root).map_err(|_| HistoryError::NoSuchRoot(root))
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay was reverting the tree to the state
    /// corresponding to the specified `version_id`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchId`] if there is no state in the history that corresponds to the
    ///   provided version id.
    pub fn view_at_id(&self, version_id: VersionId) -> Result<HistoryView<'_>> {
        self.view_at(|d| d.version_id == version_id)
            .map_err(|_| HistoryError::NoSuchId(version_id))
    }

    /// Removes all versions of the history that are older than the oldest version for which `f`
    /// returns `true`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history prior to any removals.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if there is no version for which `f` returns `true`.
    pub fn remove_versions_until(&mut self, f: impl FnMut(&Delta) -> bool) -> Result<()> {
        if let Some(ix) = self.deltas.iter().position(f) {
            for _ in 0..ix {
                self.deltas.pop_front();
            }
            Ok(())
        } else {
            Err(HistoryError::NoSuchVersion)
        }
    }

    /// Removes all versions in the history that are older than the version denoted by the provided
    /// `root`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history prior to any removals.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchRoot`] if there is no state in the history that corresponds to the
    ///   provided `root`.
    pub fn remove_versions_until_root(&mut self, root: Word) -> Result<()> {
        self.remove_versions_until(|d| d.root == root)
            .map_err(|_| HistoryError::NoSuchRoot(root))
    }

    /// Removes all versions in the history that are older than the version denoted by the provided
    /// `version_id`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history prior to any removals.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchId`] if there is no state in the history that corresponds to the
    ///   provided `version_id`.
    pub fn remove_versions_until_id(&mut self, version_id: VersionId) -> Result<()> {
        self.remove_versions_until(|d| d.version_id == version_id)
            .map_err(|_| HistoryError::NoSuchId(version_id))
    }

    /// Removes up to `count` of the oldest versions from the history.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions to be
    /// removed.
    pub fn remove_oldest_versions(&mut self, count: usize) {
        for _ in 0..count {
            self.deltas.pop_front();
        }
    }

    /// Removes all versions from the history.
    pub fn clear(&mut self) {
        self.deltas.clear();
    }
}

// HISTORY VIEW
// ================================================================================================

/// A read-only view of the history overlay on the tree at a specified place in the history.
#[derive(Debug)]
pub struct HistoryView<'history> {
    /// The index of the target version in the history.
    version_ix: usize,

    /// The history that actually stores the data that will be queried.
    history: &'history History,
}

impl<'history> HistoryView<'history> {
    /// Constructs a new history view that acts as a single overlay of the state represented by the
    /// oldest delta for which `f` returns true.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NoSuchVersion`] if no version is found in the history for which `f`
    ///   returns true.
    pub fn new_of(f: impl FnMut(&Delta) -> bool, history: &'history History) -> Result<Self> {
        if let Some(version_ix) = history.deltas.iter().position(f) {
            Ok(Self { version_ix, history })
        } else {
            Err(HistoryError::NoSuchVersion)
        }
    }

    /// Gets the value of the node in the history at the provided `index`, or returns `None` if the
    /// version does not overlay the current tree at that node.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions due to the
    /// need to traverse to find the correct overlay value.
    #[must_use]
    pub fn node_value(&self, index: &NodeIndex) -> Option<&Word> {
        self.history
            .deltas
            .iter()
            .skip(self.version_ix)
            .find_map(|v| v.nodes.get(index))
    }

    /// Gets the value of the entire leaf in the history at the specified `index`, or returns `None`
    /// if the version does not overlay the current tree at that leaf.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions due to the
    /// need to traverse to find the correct overlay value.
    #[must_use]
    pub fn leaf_value(&self, index: &LeafIndex<SMT_DEPTH>) -> Option<&CompactLeaf> {
        self.history
            .deltas
            .iter()
            .skip(self.version_ix)
            .find_map(|v| v.leaves.get(index))
    }

    /// Queries the value of a specific key in a leaf in the overlay, returning:
    ///
    /// - `None` if the version does not overlay that leaf in the current tree,
    /// - `Some(None)` if the version does overlay that leaf but the compact leaf does not contain
    ///   that value,
    /// - and `Some(Some(v))` if the version does overlay the leaf and the key exists in that leaf.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions due to the
    /// need to traverse to find the correct overlay value.
    #[must_use]
    pub fn value(&self, key: &Word) -> Option<Option<&Word>> {
        self.leaf_value(&LeafIndex::from(*key)).map(|leaf| leaf.get(key))
    }
}

// DELTA
// ================================================================================================

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

    /// The version of the tree represented by the delta.
    version_id: VersionId,

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
    fn new(root: Word, version_id: VersionId, nodes: NodeChanges, leaves: LeafChanges) -> Self {
        Self { root, version_id, nodes, leaves }
    }

    /// Gets the root of the tree created by applying the delta.
    #[must_use]
    pub fn root(&self) -> Word {
        self.root
    }

    /// Gets the version id associated with the delta.
    #[must_use]
    pub fn id(&self) -> VersionId {
        self.version_id
    }

    /// Gets the nodes that need to be altered in applying the delta.
    #[must_use]
    pub fn nodes(&self) -> &NodeChanges {
        &self.nodes
    }

    /// Gets the leaves that need to be altered in applying the delta.
    #[must_use]
    pub fn leaves(&self) -> &LeafChanges {
        &self.leaves
    }
}

// TESTS
// ================================================================================================

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
    fn roots() -> Result<()> {
        // Set up our test state
        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();
        let mut history = History::empty(2);
        let root_1: Word = rand_value();
        let root_2: Word = rand_value();
        history.add_version(root_1, 0, nodes.clone(), leaves.clone())?;
        history.add_version(root_2, 1, nodes.clone(), leaves.clone())?;

        // We should be able to get all the roots.
        let roots = history.roots();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&root_1));
        assert!(roots.contains(&root_2));

        Ok(())
    }

    #[test]
    fn knows_root() -> Result<()> {
        // Set up our test state
        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();
        let mut history = History::empty(2);
        let root_1: Word = rand_value();
        let root_2: Word = rand_value();
        history.add_version(root_1, 0, nodes.clone(), leaves.clone())?;
        history.add_version(root_2, 1, nodes.clone(), leaves.clone())?;

        // We should be able to query for existing roots.
        assert!(history.knows_root(root_1));
        assert!(history.knows_root(root_2));

        // But not for nonexistent ones.
        assert!(!history.knows_root(rand_value()));

        Ok(())
    }

    #[test]
    fn add_version() -> Result<()> {
        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        // We start with an empty state, and we should be able to add deltas up until the limit we
        // set.
        let mut history = History::empty(2);
        assert_eq!(history.num_versions(), 0);
        assert_eq!(history.max_versions(), 2);
        assert!(history.can_add_version_without_removal());

        let root_1: Word = rand_value();
        let id_1 = 0;
        history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;
        assert_eq!(history.num_versions(), 1);
        assert!(history.can_add_version_without_removal());

        let root_2: Word = rand_value();
        let id_2 = 1;
        history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;
        assert_eq!(history.num_versions(), 2);
        assert!(!history.can_add_version_without_removal());

        // At this point, adding any version should remove the oldest and return it.
        let root_3: Word = rand_value();
        let id_3 = 2;
        let removed_version = history.add_version(root_3, id_3, nodes.clone(), leaves.clone())?;
        assert!(removed_version.is_some());
        let removed_version = removed_version.unwrap();
        assert_eq!(removed_version.root(), root_1);
        assert_eq!(removed_version.id(), id_1);

        // If we then query for that first version it won't be there anymore, but the other two
        // should.
        assert!(history.get_version_by_root(root_1).is_err());
        assert!(history.get_version_by_root(root_2).is_ok());
        assert!(history.get_version_by_root(root_3).is_ok());

        // If we try and add a version with a non-monotonic version number, we should see an error.
        assert!(history.add_version(root_3, id_1, nodes, leaves).is_err());

        Ok(())
    }

    #[test]
    fn get_version() -> Result<()> {
        // We start by setting up some basic test data.
        let mut history = History::empty(2);

        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        let root_1: Word = rand_value();
        let id_1 = 0;
        history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

        let root_2: Word = rand_value();
        let id_2 = 1;
        history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

        // We can query based on an arbitrary property, finding the OLDEST version that satisfies
        // the property. In this case, we query for something that _both_ versions would satisfy,
        // and we get the older one.
        assert_eq!(history.get_version_by(|v| v.nodes().is_empty())?.root(), root_1);

        // We can also query based on two utilities for common queries.
        assert_eq!(history.get_version_by_root(root_2)?.id(), id_2);
        assert_eq!(history.get_version_by_id(id_2)?.root(), root_2);

        Ok(())
    }

    #[test]
    fn remove_versions() -> Result<()> {
        // Start by setting up the test data
        let mut history = History::empty(4);

        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        let root_1: Word = rand_value();
        let id_1 = 0;
        history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

        let root_2: Word = rand_value();
        let id_2 = 1;
        history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

        let root_3: Word = rand_value();
        let id_3 = 2;
        history.add_version(root_3, id_3, nodes.clone(), leaves.clone())?;

        let root_4: Word = rand_value();
        let id_4 = 3;
        history.add_version(root_4, id_4, nodes.clone(), leaves.clone())?;

        assert_eq!(history.num_versions(), 4);

        // We can remove all versions older than the oldest one satisfying a property. If none
        // satisfy the property then things are unchanged, but an error is raised as this is likely
        // a mistake.
        assert!(history.remove_versions_until(|v| v.id() == 7).is_err());
        assert_eq!(history.num_versions(), 4);

        history.remove_versions_until(|v| v.id() == 1)?;
        assert_eq!(history.num_versions(), 3);

        // We also have some useful methods for common ways to remove.
        history.remove_versions_until_id(2)?;
        assert_eq!(history.num_versions(), 2);

        history.remove_versions_until_root(root_4)?;
        assert_eq!(history.num_versions(), 1);

        Ok(())
    }

    #[test]
    fn remove_oldest_versions() -> Result<()> {
        // Start by setting up the test data
        let mut history = History::empty(4);

        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        let root_1: Word = rand_value();
        let id_1 = 0;
        history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

        let root_2: Word = rand_value();
        let id_2 = 1;
        history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

        let root_3: Word = rand_value();
        let id_3 = 2;
        history.add_version(root_3, id_3, nodes.clone(), leaves.clone())?;

        let root_4: Word = rand_value();
        let id_4 = 3;
        history.add_version(root_4, id_4, nodes.clone(), leaves.clone())?;

        assert_eq!(history.num_versions(), 4);

        // We can simply remove the n oldest versions
        history.remove_oldest_versions(2);
        assert_eq!(history.num_versions(), 2);

        Ok(())
    }

    #[test]
    fn clear() -> Result<()> {
        // Start by setting up the test data
        let mut history = History::empty(4);

        let nodes = NodeChanges::default();
        let leaves = LeafChanges::default();

        let root_1: Word = rand_value();
        let id_1 = 0;
        history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

        let root_2: Word = rand_value();
        let id_2 = 1;
        history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

        assert_eq!(history.num_versions(), 2);

        // We can clear the history entirely in one go.
        history.clear();
        assert_eq!(history.num_versions(), 0);

        Ok(())
    }

    #[test]
    fn view_at() -> Result<()> {
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

        history.add_version(root_1, 0, nodes_1.clone(), leaves_1.clone())?;
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
        history.add_version(root_2, 1, nodes_2.clone(), leaves_2.clone())?;
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

        history.add_version(root_3, 2, nodes_3.clone(), leaves_3.clone())?;
        assert_eq!(history.num_versions(), 3);
        assert!(!history.can_add_version_without_removal());

        // At this point, we can now grab a view into the history. This should error for an invalid
        // version.
        let invalid_root: Word = rand_value();
        let invalid_view = history.view_at(|v| v.root() == invalid_root);
        assert!(invalid_view.is_err());
        assert_eq!(invalid_view.unwrap_err(), HistoryError::NoSuchVersion);

        // We should also be able to grab a view at a valid point in the history. We grab the oldest
        // possible version to ensure that the overlay logic functions correctly.
        let view = history.view_at_root(root_1)?;

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

        // We can also, obviously, query by key instead of root.
        assert!(history.view_at_id(2).is_ok());

        Ok(())
    }
}
