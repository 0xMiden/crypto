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

mod tests;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::fmt::Debug;

use error::{HistoryError, Result};

use crate::{
    Map, Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{
            LeafIndex, NodeMutation, SMT_DEPTH,
            large_forest::{
                root::{RootValue, TreeEntry, VersionId},
                utils::MutationSet,
            },
        },
    },
};

// UTILITY TYPE ALIASES
// ================================================================================================

/// A compact leaf is a mapping from full word-length keys to word-length values, intended to be
/// stored in the leaves of an otherwise shallower merkle tree.
///
/// We use a BTreeMap as we need a guaranteed iteration order over the keys.
pub type CompactLeaf = BTreeMap<Word, Word>;

/// A collection of changes to arbitrary non-leaf nodes in a merkle tree.
///
/// All changes to nodes between versions `v` and `v + 1` must be explicitly "undone" in the
/// `NodeChanges` representing version `v`. This includes nodes that were defaulted in version `v`
/// that were given an explicit value in version `v + 1`, where the `NodeChanges` must explicitly
/// set those nodes back to the default.
///
/// Failure to do so will result in incorrect values when those nodes are queried at a point in the
/// history corresponding to version `v`.
pub type NodeChanges = Map<NodeIndex, Word>;

/// A collection of changes to arbitrary leaf nodes in a merkle tree.
///
/// While represented as a single leaf, it only contains the changes to the leaf as part of the
/// delta, and still needs to be combined with the actual leaf data for querying.
///
/// Note that if in the version of the tree represented by these `LeafChanges` had the default value
/// at the leaf, this default value must be made concrete in the map. Failure to do so will retain a
/// newer, non-default value for that leaf, and thus result in incorrect query results at this point
/// in the history.
pub type LeafChanges = Map<LeafIndex<SMT_DEPTH>, CompactLeaf>;

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
        // We allocate one more than we actually need to store to allow us to insert and THEN
        // remove, rather than the other way around. This leads to negligible increases in memory
        // usage while allowing for cleaner code.
        let deltas = VecDeque::with_capacity(max_count + 1);
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

    /// Returns all the roots that the history knows about.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present.
    ///
    /// # Complexity
    ///
    /// Calling this method provides an iterator whose consumption requires a traversal of all the
    /// versions. The method's complexity is thus `O(n)` in the number of versions.
    pub fn roots(&self) -> impl Iterator<Item = RootValue> {
        self.deltas.iter().rev().map(|d| d.root)
    }

    /// Returns the root value that corresponds to the provided `version`.
    pub fn root_for_version(&self, version: VersionId) -> Result<RootValue> {
        let ix = self.find_latest_corresponding_version(version)?;

        // The direct index is safe here because `find_latest_...` will have returned an error if
        // there is no such version, and is hence guaranteed to have returned a valid index.
        Ok(self.deltas[ix].root)
    }

    /// Adds a version to the history with the provided `root` and represented by the changes from
    /// the current tree given in `nodes` and `leaves`.
    ///
    /// If adding this version would result in exceeding `self.max_count` historical versions, then
    /// the oldest of the versions is automatically removed.
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
        root: RootValue,
        version_id: VersionId,
        nodes: NodeChanges,
        leaves: LeafChanges,
    ) -> Result<()> {
        if let Some(v) = self.deltas.iter().last() {
            if v.version_id < version_id {
                self.deltas.push_back(Delta::new(root, version_id, nodes, leaves));
                if self.num_versions() > self.max_versions() {
                    self.deltas.pop_front();
                }

                Ok(())
            } else {
                Err(HistoryError::NonMonotonicVersions(version_id, v.version_id))
            }
        } else {
            self.deltas.push_back(Delta::new(root, version_id, nodes, leaves));

            Ok(())
        }
    }

    /// Adds a version to the history and represented by the changes from the current tree given
    /// `mutations`.
    ///
    /// If adding this version would result in exceeding `self.max_count` historical versions, then
    /// the oldest of the versions is automatically removed.
    ///
    /// # Gotchas
    ///
    /// When constructing the `mutations`, keep in mind that the set must contain entries for the
    /// **default value of a node or leaf** at any position where the tree was sparse in the state
    /// represented by `root`. If this is not done, incorrect values may be returned.
    ///
    /// This is necessary because the changes are the _reverse_ from what one might expect. Namely,
    /// the changes in a given version `v` must "_revert_" the changes made in the transition from
    /// version `v` to version `v + 1`.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NonMonotonicVersions`] if the provided version is not greater than the
    ///   previously added version.
    pub fn add_version_from_mutation_set(
        &mut self,
        version_id: VersionId,
        mutations: MutationSet,
    ) -> Result<()> {
        // The leaf changes must be grouped by parent leaf when being inserted, so we do that here.
        let mut leaf_changes = LeafChanges::default();
        for (key, val) in mutations.new_pairs {
            leaf_changes.entry(LeafIndex::from(key)).or_default().insert(key, val);
        }

        // The node changes are more complex, as we have to explicitly handle reversions to empty
        // specially.
        let node_changes: NodeChanges = mutations
            .node_mutations
            .into_iter()
            .map(|(ix, m)| match m {
                NodeMutation::Removal => (ix, *EmptySubtreeRoots::entry(SMT_DEPTH, ix.depth())),
                NodeMutation::Addition(n) => (ix, n.hash()),
            })
            .collect();

        // Now we can simply delegate to the standard function.
        self.add_version(mutations.new_root, version_id, node_changes, leaf_changes)
    }

    /// Returns the index in the sequence of deltas of the version that corresponds to the provided
    /// `version_id`.
    ///
    /// To "correspond" means that it either has the provided `version_id`, or is the newest version
    /// with a `version_id` less than the provided id. In either case, it is the correct version to
    /// be used to query the tree state in the provided `version_id`.
    ///
    /// # Complexity
    ///
    /// Finding the latest corresponding version in the history requires a linear traversal of the
    /// history entries, and hence has complexity `O(n)` in the number of versions.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::HistoryEmpty`] if the history is empty and hence there is no version to
    ///   find.
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version_id` due to `version_id` being older than the
    ///   oldest version stored.
    fn find_latest_corresponding_version(&self, version_id: VersionId) -> Result<usize> {
        // If the version is older than the oldest, we error.
        if let Some(oldest_version) = self.deltas.front() {
            if oldest_version.version_id > version_id {
                return Err(HistoryError::VersionTooOld);
            }
        } else {
            return Err(HistoryError::VersionTooOld);
        }

        let ix = self
            .deltas
            .iter()
            .position(|d| d.version_id > version_id)
            .unwrap_or_else(|| self.num_versions())
            .checked_sub(1)
            .expect(
                "Subtraction should not overflow as we have ruled out the no-version \
                case, and in the other cases the left operand will be >= 1",
            );

        Ok(ix)
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay was reverting the tree to the state
    /// corresponding to the specified `version_id`.
    ///
    /// Note that the history may not contain a version that directly corresponds to `version_id`.
    /// In such a case, the view will instead use the newest version coherent with the provided
    /// `version_id`, as this is the correct version for the provided id. Note that this will be
    /// incorrect if the versions stored in the history do not represent contiguous changes from the
    /// current tree.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version_id` due to `version_id` being older than the
    ///   oldest version stored.
    pub fn get_view_at(&self, version_id: VersionId) -> Result<HistoryView<'_>> {
        HistoryView::new_of(version_id, self)
    }

    /// Removes all versions in the history that are older than the version denoted by the provided
    /// `version_id`.
    ///
    /// If `version_id` is not a version known by the history, it will keep the newest version that
    /// is capable of serving as that version in queries.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history prior to any removals.
    pub fn truncate(&mut self, version_id: VersionId) -> usize {
        // We start by getting the index to truncate to, though it is not an error to remove
        // something too old.
        let truncate_ix = self.find_latest_corresponding_version(version_id).unwrap_or(0);

        for _ in 0..truncate_ix {
            self.deltas.pop_front();
        }

        truncate_ix
    }

    /// Removes all versions from the history.
    pub fn clear(&mut self) {
        self.deltas.clear();
    }
}

/// The functions in this impl block are specifically used for testing and are not available for
/// general API usage.
#[cfg(test)]
impl History {
    /// Returns `true` if `root` is in the history and `false` otherwise.
    #[must_use]
    pub fn is_known_root(&self, root: RootValue) -> bool {
        self.deltas.iter().any(|r| r.root == root)
    }
}

// HISTORY VIEW
// ================================================================================================

/// A read-only view of the history overlay on the tree at a specified place in the history.
#[derive(Debug)]
pub struct HistoryView<'history> {
    /// The version of the history pointed to by the history view.
    version: VersionId,

    /// The index of the target version in the history.
    version_ix: usize,

    /// The history that actually stores the data that will be queried.
    history: &'history History,
}

impl<'history> HistoryView<'history> {
    /// Constructs a new history view that acts as a single overlay of the state represented by the
    /// history at the provided `version`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version`.
    fn new_of(version: VersionId, history: &'history History) -> Result<Self> {
        let version_ix = history.find_latest_corresponding_version(version)?;
        Ok(Self { version, version_ix, history })
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

    /// Gets a single leaf that represents the delta from the current version of the tree to the
    /// point in the history at the specified `index`.
    ///
    /// If the specified version does not overlay the current tree at that leaf, it will return an
    /// empty compact leaf.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions due to the
    /// need to traverse to find the correct overlay value.
    #[must_use]
    pub fn leaf_delta(&self, index: &LeafIndex<SMT_DEPTH>) -> CompactLeaf {
        let mut leaf = CompactLeaf::default();

        // We want to keep the _oldest_ change for any particular key in a leaf.
        for delta in self.history.deltas.iter().skip(self.version_ix) {
            if let Some(leaf_delta) = delta.leaves.get(index) {
                for (key, value) in leaf_delta {
                    leaf.entry(*key).or_insert(*value);
                }
            }
        }

        leaf
    }

    /// Queries the value of a specific `key` in a leaf in the overlay, returning the value for that
    /// `key` if it has been changed, and [`None`] otherwise.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions due to the
    /// need to traverse to find the correct overlay value.
    #[must_use]
    pub fn value(&self, key: &Word) -> Option<Word> {
        self.leaf_delta(&LeafIndex::from(*key)).get(key).copied()
    }

    /// Returns an iterator which yields the entries that are changed by this view.
    ///
    /// This iterator yields entries in an order such that they are sorted by their leaf index, and
    /// entries that share a leaf index are sorted by key. It includes key-value pairs where the
    /// value is the empty word, as these are necessary for merging with entries in the full tree.
    pub fn entries(&self) -> impl Iterator<Item = TreeEntry> + 'history {
        // It is safe to call this directly here as the construction of `HistoryView` has ensured
        // that we have such a version.
        HistoricalEntriesIterator::new(self.history, self.version)
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
struct Delta {
    /// The root of the tree in the `version` corresponding to the application of the reversions in
    /// this delta to the previous tree state.
    root: RootValue,

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
    fn new(
        root: RootValue,
        version_id: VersionId,
        nodes: NodeChanges,
        leaves: LeafChanges,
    ) -> Self {
        Self { root, version_id, nodes, leaves }
    }
}

// ENTRIES ITERATOR
// ================================================================================================

/// An iterator over the historical value for each changed entry at a given point in the history.
///
/// This iterator yields entries in an order such that they are sorted by their leaf index, and
/// entries that share a leaf index are sorted by key. It includes key-value pairs where the value
/// is the empty word, as these are necessary for merging with entries in the full tree.
#[derive(Debug)]
pub struct HistoricalEntriesIterator<'history> {
    /// The history over which the iterator is defined.
    history: &'history History,

    /// The version in the history to be working from.
    version: VersionId,

    /// The set of all changed leaves in the deltas that make up this iterator that have not yet
    /// been visited by the iterator.
    ///
    /// We use a BTreeSet specifically as we need sorted iteration behavior.
    changed_leaves: BTreeSet<LeafIndex<SMT_DEPTH>>,

    /// The current state of the iterator's iteration behavior.
    position: HistoricalEntriesIteratorState,
}

impl<'history> HistoricalEntriesIterator<'history> {
    /// Creates a new historical entries iterator that represents a coherent set of delta entries at
    /// the position in the history given by `version_ix`.
    fn new(history: &'history History, version: VersionId) -> Self {
        let changed_leaves = history
            .deltas
            .iter()
            .skip(
                history
                    .find_latest_corresponding_version(version)
                    .expect("Caller has guaranteed existence of a corresponding version"),
            )
            .flat_map(|d| d.leaves.keys())
            .copied()
            .collect();

        // We want to start not pointing to any leaf as we can only advance when `next` is called.
        let current_leaf_index = HistoricalEntriesIteratorState::NotInLeaf;

        Self {
            history,
            version,
            changed_leaves,
            position: current_leaf_index,
        }
    }
}

impl<'history> Iterator for HistoricalEntriesIterator<'history> {
    type Item = TreeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.position {
            HistoricalEntriesIteratorState::NotInLeaf => {
                // If we are not inside a leaf we need to see if we can become so.
                if let Some(ix) = self.changed_leaves.pop_first() {
                    // If we can move into a new leaf, we transition the state into that leaf and
                    // return the entry.
                    let leaf_delta = self
                        .history
                        .get_view_at(self.version)
                        .expect(
                            "Version was guaranteed to exist before construction of the iterator",
                        )
                        .leaf_delta(&ix);

                    // As we are querying based on `changed_leaves`, each of the `leaf_delta`
                    // results should contain at least one item.
                    let (key, value) = leaf_delta
                        .first_key_value()
                        .expect("At least one item guaranteed by construction");
                    let item = TreeEntry { key: *key, value: *value };

                    // At this point we now have the item, but we need to set up the state to point
                    // to this item as we return it.
                    self.position = HistoricalEntriesIteratorState::InLeaf { value: leaf_delta };

                    Some(item)
                } else {
                    // If we cannot move to a new leaf index, the iterator is done.
                    None
                }
            },
            HistoricalEntriesIteratorState::InLeaf { value } => {
                // If we are already inside a leaf, there are two cases that can occur when
                // advancing.
                value.pop_first().expect("InLeaf implies there is at least one entry in value");
                if let Some((k, v)) = value.first_key_value() {
                    // The first (and simplest) case is that we have another entry in the current
                    // leaf value. In this case, the item is just the front of the leaf value, and
                    // we re-write the key to point to it while leaving the leaf index the same.
                    let item = TreeEntry { key: *k, value: *v };

                    Some(item)
                } else {
                    // Here, we have no further entries in the current leaf, so we have to check if
                    // there is another leaf to move to. In other words, we are implicitly in the
                    // `NotInLeaf` state, so we can just call `next` recursively.
                    //
                    // This is not a stack overflow risk as it should only ever recurse once.
                    self.position = HistoricalEntriesIteratorState::NotInLeaf;
                    self.next()
                }
            },
        }
    }
}

/// The state that tracks where the iterator is in the iteration process.
#[derive(Debug)]
enum HistoricalEntriesIteratorState {
    /// It currently does not point to any underlying leaf index.
    NotInLeaf,

    /// It is currently pointing to the specified key within the specified index.
    InLeaf {
        /// The combined full delta that represents the compact leaf.
        value: CompactLeaf,
    },
}
