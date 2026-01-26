//! A high-performance sparse merkle tree forest with pluggable backends.
//!
//! # Semantic Layout
//!
//! Much like `SparseMerkleTree`, the forest stores trees of depth 64 that use the compact leaf
//! optimization to uniquely store 256-bit elements. This reduces both the size of a merkle path,
//! and the computational work necessary to perform queries into the trees.
//!
//! # Storing Trees and Versions
//!
//! The usage of an SMT forest is conceptually split into two parts: a collection that is able to
//! store **multiple, unrelated trees**, and a container for **multiple versions of those trees**.
//! Both of these use-cases are supported by the forest, but have an explicit delineation between
//! them in both the API and the implementation. This has two impacts that a client of the forest
//! must understand.
//!
//! - While, when using a [`Backend`] that can persist data, **only the current full tree state is
//!   persisted**, while **the historical data will not be**. This is designed into the structure of
//!   the forest, and does not depend on the choice of storage backend.
//! - It is more expensive to query a given tree at an older point in its history than it is to
//!   query it at a newer point, and querying at the current tree will always take the least time.
//!
//! # Lineages
//!
//! We term a set of trees where each is derived from the previous version to be a **lineage**. A
//! single lineage semantically contains the **full information** on the current state of the tree,
//! alongside a set of deltas which describe how to change that full tree to return to a historical
//! state of that tree.
//!
//! While any given [`Backend`] may choose to share data between lineages, this behavior is not
//! guaranteed, and must not be relied upon.
//!
//! # Tree Identification
//!
//! It is possible for multiple lineages to contain a tree with identical leaves and hence an
//! identical root. As we store lineages separately, we need some way to specify which instance of a
//! given root we mean.
//!
//! This is done by identifying trees using the [`TreeId`], which combines the tree's root value
//! with a user-provided identifier that tags the tree with a 'domain'. This allows distinguishing
//! between otherwise identical trees. Users must take care to ensure that each domain is unique, as
//! reusing them will result in overwriting data in the wrong domain, and that queries may return
//! incorrect results.
//!
//! # Data Storage
//!
//! The SMT forest is parametrized over the [`Backend`] implementation that it uses. These backends
//! may have significantly varied performance characteristics, and hence any performance analysis of
//! the forest should be done in conjunction with a specific backend. The forest itself takes pains
//! to not make any assumptions about properties of the backend in use.
//!
//! Take care to read the documentation of the specific [`Backend`] that you are planning to use in
//! order to understand its performance, gotchas, and other such details.

// TODO Usage examples for in-memory.
// TODO Performance documentation.

mod backend;
mod error;
mod history;
mod operation;
mod property_tests;
mod root;
mod tests;
mod utils;

use alloc::boxed::Box;
use core::iter::once;
use std::num::NonZeroU8;

pub use backend::{Backend, BackendError, memory::InMemoryBackend};
pub use error::{LargeSmtForestError, Result};
pub use operation::{ForestOperation, SmtForestUpdateBatch, SmtUpdateBatch};
pub use root::{RootInfo, TreeId, VersionId};

use crate::{
    EMPTY_WORD, Map, Set, Word,
    merkle::{
        NodeIndex, SparseMerklePath,
        smt::{
            LeafIndex, SMT_DEPTH, SmtLeaf, SmtProof,
            large_forest::{
                history::{CompactLeaf, History, HistoryView},
                root::{LineageId, RootValue, TreeEntry, TreeWithRoot, UniqueRoot},
            },
        },
    },
};
// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// A high-performance forest of sparse merkle trees with pluggable storage.
///
/// # Current and Frozen Trees
///
/// Trees in the forest fall into two categories:
///
/// 1. **Current:** These trees represent the latest version of their 'tree lineage' and can be
///    modified to generate a new tree version in the forest.
/// 2. **Frozen:** These are historical versions of trees that are no longer current, and are
///    considered 'frozen' and hence cannot be modified to generate a new tree version in the
///    forest. This is because being able to do so would effectively create a "fork" in the history,
///    and hence allow the forest to yield potentially invalid responses with regard to the
///    blockchain history.
///
/// The API is designed to avoid any possibility of modifying frozen trees in the forest, and hence
/// ensure the correctness of the history stored in the forest.
///
/// # Performance
///
/// The performance characteristics of this forest depend heavily on the choice of underlying
/// [`Backend`] implementation. Where something more specific can be said about a particular method
/// call, the documentation for that method will state it.
#[allow(dead_code)] // Temporarily
#[derive(Debug)]
pub struct LargeSmtForest<B: Backend> {
    /// The configuration for the forest's behaviour.
    config: Config,

    /// The backend for storing the full trees that exist as part of the forest. It makes no
    /// guarantees as to where the tree data is stored, and **must not be exposed** in the API of
    /// the forest for correctness.
    backend: B,

    /// The container for the in-memory data associated with each lineage in the forest.
    ///
    /// It must contain an entry for every tree lineage in the forest.
    lineage_data: Map<LineageId, LineageData>,

    /// A set tracking which lineage which lineages have histories containing actual deltas in
    /// order to speed up querying.
    ///
    /// It must always be maintained as a strict subset of `lineage_data.keys()`.
    non_empty_histories: Set<LineageId>,
}

// TODO: Invariant docs for all methods.

// CONSTRUCTION AND BASIC QUERIES
// ================================================================================================

/// These functions deal with the creation of new forest instances, and hence rely on the ability to
/// query storage to do so.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: Backend> LargeSmtForest<B> {
    /// Constructs a new forest backed by the provided `backend` using the default [`Config`] for
    /// the forest's behavior.
    ///
    /// This constructor will treat whatever state is contained within the provided `backend` as the
    /// starting state for the forest. This means that, if you pass a newly-initialized storage, the
    /// forest will start in an empty state. Similarly, if you pass a `backend` that already
    /// contains some data (loaded from disk, for example), then the forest will start in that state
    /// instead.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Other`] if the forest cannot be started up correctly using the
    ///   provided `backend`.
    pub fn new(backend: B) -> Result<Self> {
        Self::with_config(backend, Config::default())
    }

    /// Constructs a new forest backed by the provided `backend` and configuring behavior using the
    /// provided `config`.
    ///
    /// This constructor will treat whatever state is contained within the provided `backend` as the
    /// starting state for the forest. This means that, if you pass a newly-initialized storage, the
    /// forest will start in an empty state. Similarly, if you pass a `backend` that already
    /// contains some data (loaded from disk, for example), then the forest will start in that state
    /// instead.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Other`] if the forest cannot be started up correctly using the
    ///   provided `backend`.
    pub fn with_config(backend: B, config: Config) -> Result<Self> {
        // The lineages at initialization time are whichever ones the backend knows about. To that
        // end, we read from the backend and construct the starting state for each known lineage.
        let lineage_data = backend
            .trees()?
            .map(|t| {
                let data = LineageData {
                    history: History::empty(config.max_historical_versions),
                    latest_version: t.version(),
                    latest_root: t.root(),
                };
                (t.lineage(), data)
            })
            .collect::<Map<LineageId, LineageData>>();

        // As no backend is able to preserve history, we can unconditionally initialize the tracking
        // for non-empty histories as empty.
        let non_empty_histories = Set::default();

        Ok(Self {
            config,
            backend,
            lineage_data,
            non_empty_histories,
        })
    }
}

/// These methods provide the ability to perform basic operations on the forest without the need to
/// query the backend.
///
/// # Performance
///
/// All of these methods can be performed fully in-memory, and hence their performance is
/// predictable on a given machine regardless of the choice of [`Backend`] instance being used by
/// the forest.
impl<B: Backend> LargeSmtForest<B> {
    /// Returns an iterator that yields all the (uniquely identified) roots that the forest knows
    /// about, including those from historical versions.
    ///
    /// The iteration order of these roots is unspecified.
    pub fn roots(&self) -> impl Iterator<Item = UniqueRoot> {
        // As the history container does not deal in roots with domains, we have to attach the
        // corresponding domain to each root, and do this as lazily as possible to avoid
        // materializing more things than we need to.
        self.lineage_data
            .iter()
            .flat_map(|(l, d)| d.roots().map(|r| UniqueRoot::new(*l, r)))
    }

    /// Gets the latest version of the tree for the provided `lineage`, if that lineage is in the
    /// forest, or returns [`None`] otherwise.
    pub fn latest_version(&self, lineage: LineageId) -> Option<VersionId> {
        self.lineage_data.get(&lineage).map(|d| d.latest_version)
    }

    /// Returns an iterator that yields the root values for trees within the specified `lineage`, or
    /// [`None`] if the lineage is not known.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present. The current root of the lineage will always
    /// be the first item yielded by the iterator.
    pub fn lineage_roots(&self, lineage: LineageId) -> Option<impl Iterator<Item = RootValue>> {
        self.lineage_data.get(&lineage).map(|d| d.roots())
    }

    /// Gets the value root of the newest tree in the provided `lineage`, if that lineage is in the
    /// forest, or returns [`None`] otherwise.
    pub fn latest_root(&self, lineage: LineageId) -> Option<RootValue> {
        self.lineage_data.get(&lineage).map(|d| d.latest_root)
    }

    /// Returns the number of trees in the forest that have unique identity.
    ///
    /// This is **not** the number of unique tree lineages in the forest, as it includes all
    /// historical trees as well. For that, see [`Self::lineage_count`].
    pub fn tree_count(&self) -> usize {
        self.roots().count()
    }

    /// Returns the number of unique tree lineages in the forest.
    ///
    /// This is **not** the number of unique trees in the forest, as it does not include all
    /// versions in each lineage. For that, see [`Self::tree_count`].
    pub fn lineage_count(&self) -> usize {
        self.lineage_data.len()
    }

    /// Returns data describing what information the forest knows about the provided `root`.
    pub fn root_info(&self, root: TreeId) -> RootInfo {
        if let Some(d) = self.lineage_data.get(&root.lineage()) {
            if d.latest_version == root.version() {
                RootInfo::LatestVersion(d.latest_root)
            } else if root.version() > d.latest_version {
                RootInfo::Missing
            } else {
                match d.history.root_for_version(root.version()) {
                    Ok(r) => RootInfo::HistoricalVersion(r),
                    Err(_) => RootInfo::Missing,
                }
            }
        } else {
            RootInfo::Missing
        }
    }

    /// Removes all tree versions in the forest that are older than the provided `version`, but
    /// always retains the latest tree in each lineage.
    pub fn truncate(&mut self, version: VersionId) {
        let mut newly_empty = Set::default();

        self.non_empty_histories.iter().for_each(|l| {
            if let Some(d) = self.lineage_data.get_mut(l)
                && d.truncate(version)
            {
                newly_empty.insert(*l);
            }
        });

        self.non_empty_histories.extend(newly_empty);
    }
}

// QUERIES
// ================================================================================================

/// These methods pertain to non-mutating queries about the data stored in the forest. They differ
/// from the simple queries in the previous block by requiring access to the backend to function.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: Backend> LargeSmtForest<B> {
    /// Returns an opening for the specified `key` in the specified `tree`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    /// - [`LargeSmtForestError::Merkle`] If there is insufficient data in the specified `tree` to
    ///   provide an opening for `key`.
    pub fn open(&self, tree: TreeId, key: Word) -> Result<SmtProof> {
        // We want to return an error if the lineage is unknown to comply with the stated contract
        // for the function.
        let lineage_data = self
            .lineage_data
            .get(&tree.lineage())
            .ok_or(LargeSmtForestError::UnknownLineage(tree.lineage()))?;

        // We then check if the version exists in the forest. We do this before fetching the full
        // tree as to do so otherwise would represent a possible denial-of-service vector.
        if tree.version() == lineage_data.latest_version {
            // In this case we can service the opening directly from the backend as the query is for
            // the latest version of the tree.
            self.backend.open(tree.lineage(), key).map_err(Into::into)
        } else if let Ok(view) = lineage_data.history.get_view_at(tree.version()) {
            // We start by computing the relevant leaf index and getting the opening from the full
            // tree to do our (potentially) most-expensive work up front.
            let leaf_index = LeafIndex::from(key);
            let opening = self
                .backend
                .open(tree.lineage(), key)
                .map_err(Into::<LargeSmtForestError>::into)?;

            // We compute the new leaf and new path by applying any reversions from the history on
            // top of the current state.
            let new_leaf = self.merge_leaves(opening.leaf(), &view.leaf_delta(&leaf_index))?;
            let new_path = self.merge_paths(leaf_index, opening.path(), view)?;

            // Finally we can compose our combined opening.
            Ok(SmtProof::new(new_path, new_leaf)?)
        } else {
            // In this case, either the version in `tree` is newer than the latest we know about, so
            // we can't provide an opening, or it is not serviceable by the history. In either case,
            // the specified tree is unknown to the forest.
            Err(LargeSmtForestError::UnknownTree(tree))
        }
    }

    /// Returns the value associated with the provided `key` in the specified `tree`, or [`None`] if
    /// there is no value corresponding to the provided `key` in that tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn get(&self, tree: TreeId, key: Word) -> Result<Option<Word>> {
        // We want to return an error if the lineage is unknown to comply with the stated contract
        // for the function.
        let lineage_data = self
            .lineage_data
            .get(&tree.lineage())
            .ok_or(LargeSmtForestError::UnknownLineage(tree.lineage()))?;

        if tree.version() == lineage_data.latest_version {
            // In this case we can service the opening directly from the backend as the query is for
            // the latest version of the tree.
            self.backend.get(tree.lineage(), key).map_err(Into::into)
        } else if let Ok(view) = lineage_data.history.get_view_at(tree.version()) {
            // We prioritize the value in the history if one exists, falling back to the full tree
            // if none does. We don't use `or` here because we don't want to query the backend
            // unless we have to, and we can't use `or_else` due to lack of support for `Result`.
            let result = if let Some(value) = view.value(&key) {
                // If the history value is an empty word, the value was unset in the historical tree
                // version, so we have to conform to our interface by returning `None` here.
                if value == EMPTY_WORD { None } else { Some(value) }
            } else {
                self.backend.get(tree.lineage(), key)?
            };

            // We can just return that directly.
            Ok(result)
        } else {
            // In this case, either the version in `tree` is newer than the latest we know about, so
            // we can't provide an opening, or it is not serviceable by the history. In either case,
            // the specified tree is unknown to the forest.
            Err(LargeSmtForestError::UnknownTree(tree))
        }
    }

    /// Returns the number of populated entries in the specified `tree`.
    ///
    /// # Performance
    ///
    /// Due to the way that tree data is stored, this method exhibits a split performance profile.
    ///
    /// - If querying for a `tree` that is the latest in its lineage, the time to return a result
    ///   should be constant.
    /// - If querying for a `tree` that is a historical version, the time to return a result will be
    ///   linear in the number of entries in the tree. This is because an overlaid iterator has to
    ///   be created to yield the correct entries for the historical version, and then queried for
    ///   its length.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn entry_count(&self, _tree: TreeId) -> Result<usize> {
        // TODO: This needs to
        //   1. Check that the tree corresponds to a known lineage.
        //   2. Check that the tree corresponds to an available version.
        //   3. Fast path for the current tree in each lineage by calling into the backend.
        //   4. If not, call `self.entries()?.count()` to yield the result.

        todo!("LargeSmtForest::entry_count")
    }

    /// Returns an iterator that yields the entries in the specified `tree`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn entries<I: Iterator<Item = TreeEntry>>(&self, _tree: TreeId) -> Result<I> {
        // TODO Turn this signature back to an `impl Iterator<...>` once there is a body. `impl`
        //      generics are fussy alongside `todo!`s.
        //
        // TODO: This needs to
        //   1. Check that the tree corresponds to a known lineage.
        //   2. Check that the tree corresponds to an available version.
        //   3. Call `self.entries_iterator()` to yield the actual iterator.

        todo!("LargeSmtForest::entries")
    }
}

// SINGLE-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to a single tree in the forest. They
/// exploit parallelism within the single target tree wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
#[allow(dead_code)] // Temporarily
impl<B: Backend> LargeSmtForest<B> {
    /// Adds a new `lineage` to the tree, creating an empty tree and modifying it as specified by
    /// `updates`, with the result taking the provided `new_version`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if the provided `lineage` is the same as an
    ///   already-known lineage.
    /// - [`BackendError::Merkle`] if the provided `updates` cannot be applied to the empty tree.
    pub fn add_lineage(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        // We can immediately add lineage in the backend, as by its contract it should return
        // `DuplicateLineage` if the new lineage is a duplicate. We forward that, and any other
        // errors as this is the correct behavior for conformant backends, relying on the conversion
        // operations between `BackendError` and the forest's error type.
        let tree_info = self.backend.add_lineage(lineage, new_version, updates)?;

        // We then construct the lineage tracking data and shove it into the corresponding map. The
        // history is guaranteed to be empty here, so we do not need to put an entry in the
        // non-empty histories set.
        let lineage_data = LineageData {
            history: History::empty(self.config.max_historical_versions),
            latest_version: tree_info.version(),
            latest_root: tree_info.root(),
        };
        self.lineage_data.insert(lineage, lineage_data);

        Ok(tree_info)
    }

    /// Performs the provided `updates` on the latest tree in the specified `lineage`, adding a
    /// single new root to the forest (corresponding to `new_version`) for the entire batch, and
    /// returning the data for the new root of the tree.
    ///
    /// If applying the provided `operations` results in no changes to the tree, then the root data
    /// will be returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BadVersion`] if the `new_version` is older than the latest version
    ///   for the provided `lineage`.
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    pub fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        // We initially check that the lineage is known and that the version is greater than the
        // last known version for that lineage.
        let lineage_data = if let Some(lineage_data) = self.lineage_data.get_mut(&lineage) {
            if lineage_data.latest_version < new_version {
                lineage_data
            } else {
                return Err(LargeSmtForestError::BadVersion(
                    new_version,
                    lineage_data.latest_version,
                ));
            }
        } else {
            return Err(LargeSmtForestError::UnknownLineage(lineage));
        };

        // We now know that we have a valid lineage and a valid version, so we perform the update in
        // the backend.
        let reversion_set = self.backend.update_tree(lineage, new_version, updates)?;

        // The new root of the latest tree is actually given by the **old root** in our reverse
        // mutation set.
        let updated_root = reversion_set.old_root;

        // The mutation set that we get back is the set of changes to revert the tree changes, so we
        // use these to create a new version in the history. The version here is the version we are
        // moving _away_ from, and so we get it from the lineage data before we overwrite it with
        // the new version.
        lineage_data
            .history
            .add_version_from_mutation_set(lineage_data.latest_version, reversion_set)?;

        // Now we just have to update the other portions of the lineage data in place...
        lineage_data.latest_root = updated_root;
        lineage_data.latest_version = new_version;

        // ...and return the correct value.
        Ok(TreeWithRoot::new(lineage, new_version, updated_root))
    }
}

// MULTI-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to multiple trees in the forest at once.
/// They exploit parallelism both between trees and within trees wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: Backend> LargeSmtForest<B> {
    /// Performs the provided `updates` on the forest, adding at most one new root with version
    /// `new_version` to the forest for each target root in `updates` and returning a mapping
    /// from old root to the new root data.
    ///
    /// If applying the associated batch to any given lineage in the forest results in no changes to
    /// that tree, the initial root for that lineage will be returned and no new tree will be
    /// allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] If any lineage in the batch of modifications is
    ///   one that is not known by the forest.
    pub fn update_forest(
        &mut self,
        _new_version: VersionId,
        _updates: SmtForestUpdateBatch,
    ) -> Result<Map<TreeId, TreeWithRoot>> {
        todo!("LargeSmtForest::modify_forest")
    }
}

// INTERNAL UTILITY FUNCTIONS
// ================================================================================================

/// This block contains internal functions that exist to de-duplicate or modularize functionality
/// within the forest. These should not be exposed.
impl<B: Backend> LargeSmtForest<B> {
    /// Applies the provided `historical_delta` on top of the provided `full_tree_leaf` to produce
    /// the correct leaf for a historical opening.
    fn merge_leaves(
        &self,
        full_tree_leaf: &SmtLeaf,
        historical_delta: &CompactLeaf,
    ) -> Result<SmtLeaf> {
        let mut leaf_entries = Map::new();
        leaf_entries.extend(full_tree_leaf.to_entries().map(|(k, v)| (*k, *v)));
        leaf_entries.extend(historical_delta);

        Ok(SmtLeaf::new(leaf_entries.into_iter().collect(), full_tree_leaf.index())?)
    }

    /// Applies any historical changes contained in `history_view` on top of the merkle path
    /// obtained from the full tree to produce the correct path for a historical opening.
    fn merge_paths(
        &self,
        leaf_index: LeafIndex<SMT_DEPTH>,
        full_tree_path: &SparseMerklePath,
        history_view: HistoryView,
    ) -> Result<SparseMerklePath> {
        let mut path_elems = [EMPTY_WORD; SMT_DEPTH as usize];
        let mut current_node_ix = NodeIndex::from(leaf_index);
        for depth in (1..=SMT_DEPTH).rev() {
            // This is the sibling node of the currently-tracked node. In other words, it is the
            // node that needs to become part of the path.
            let path_node_ix = current_node_ix.sibling();

            if let Some(historical_value) = history_view.node_value(&path_node_ix) {
                // If there is a historical value we need to use it, and so we write it to the
                // correct slot in the path elements array.
                path_elems[depth as usize - 1] = *historical_value;
            } else {
                // If there isn't a historical value, we should delegate to the corresponding
                // element in the path from the full-tree opening.
                //
                // We know here that the possible values of `depth` in the loop range from 64 to
                // 1 (inclusive). All values in this range are non-zero, and hence we do not
                // need to perform the check when constructing our NonZeroU8 for the indexing
                // operation.
                path_elems[depth as usize - 1] =
                    full_tree_path.at_depth(unsafe { NonZeroU8::new_unchecked(depth) })?
            }

            // We then need to move upward in the tree of the nodes we know.
            current_node_ix = current_node_ix.parent();
        }

        // Now that we have filled in our `path_elems` we can use the construction of a sparse
        // merkle path from a sized iterator, and thus not compute the mask ourselves. We
        // reverse the iterator to make it go from deepest to shallowest as required.
        Ok(SparseMerklePath::from_sized_iter(path_elems.into_iter().rev())?)
    }

    /// This internal function creates the iterator over entries for a given tree in the forest but
    /// **does not** perform the check for the lineage existing.
    ///
    /// It exists to avoid redundant checks of the tree's existence, but as a result must have that
    /// particular precondition checked beforehand.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    #[allow(dead_code)] // Temporary
    fn entries_iterator(&self, tree: TreeId) -> Result<impl Iterator<Item = TreeEntry> + '_> {
        EntriesIterator::new_without_history(self, tree)
    }
}

// TESTING FUNCTIONALITY
// ================================================================================================

/// This block contains functions that are exclusively for testing, providing some extra tools to
/// inspect the internal state of the forest that should not be visible to users.
#[cfg(test)]
impl<B: Backend> LargeSmtForest<B> {
    /// Gets an immutable reference to the underlying configuration object for the forest.
    pub fn get_config(&self) -> &Config {
        &self.config
    }

    /// Gets an immutable reference to the underlying backend of the forest.
    pub fn get_backend(&self) -> &B {
        &self.backend
    }

    /// Gets a mutable reference to the underlying backend of the forest.
    pub fn get_backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Gets the history container corresponding to the provided `lineage`.
    ///
    /// # Panics
    ///
    /// - If the `lineage` is not one that the tree knows about.
    pub fn get_history(&self, lineage: LineageId) -> &History {
        self.lineage_data
            .get(&lineage)
            .map(|d| &d.history)
            .unwrap_or_else(|| panic!("Lineage {lineage} had no data"))
    }
}

// LINEAGE DATA
// ================================================================================================

/// The data that the forest stores in memory for each lineage of trees.
#[derive(Clone, Debug)]
struct LineageData {
    /// The historical overlays for the lineage.
    pub history: History,

    /// The version associated with the latest tree in the lineage.
    pub latest_version: VersionId,

    /// The value of the root for the latest tree in the lineage.
    pub latest_root: RootValue,
}

impl LineageData {
    /// Gets an iterator that yields each root in the lineage.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present. The current root of the lineage will always
    /// be the first item yielded by the iterator.
    fn roots(&self) -> impl Iterator<Item = RootValue> {
        once(self.latest_root).chain(self.history.roots())
    }

    /// Truncates the information on this tree to the provided `version`, returning `true` if the
    /// history is empty after truncation, and `false` otherwise.
    ///
    /// In the case that the version of the latest tree in the lineage is older than `version`, this
    /// current version is always retained.
    pub(super) fn truncate(&mut self, version: VersionId) -> bool {
        if version >= self.latest_version {
            // Truncation in the history is defined such that it never removes a version that could
            // possibly serve as the latest delta for a newer version. This is because it cannot
            // safely know if a version `v` is between the latest delta `d` and the current version
            // `c`, as it has no knowledge of the current version.
            //
            // Thus, if we have a version `v` such that `d <= v < c`, we need to retain the
            // reversion delta `d` in the history to correctly service queries for `v`. If, however,
            // we have `d < c <= v` we need to explicitly remove the last delta as well.
            //
            // To that end, we handle the latter case first, by explicitly calling
            // `History::clear()`.
            self.history.clear();
            true
        } else {
            // The other case is `v < c`, which is handled simply by the truncation mechanism in the
            // history as we want. In other words, it retains the necessary delta, and so we can
            // just call it here.
            self.history.truncate(version);
            false
        }
    }
}

// FOREST CONFIG
// ================================================================================================

/// The configuration for the forest's behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The maximum number of historical versions that the forest will keep for any given lineage.
    max_historical_versions: usize,
}

/// This impl block contains the builder functions for the configuration options.
impl Config {
    /// Sets the maximum number of historical versions that the forest will store for any given
    /// lineage.
    ///
    /// This defaults to 10.
    pub fn with_max_history_versions(mut self, max_historical_versions: usize) -> Self {
        self.max_historical_versions = max_historical_versions;
        self
    }
}

/// This impl block contains the accessors for the configuration options.
impl Config {
    /// Gets the maximum number of historical versions that the forest will keep for any given
    /// lineage.
    pub fn max_history_versions(&self) -> usize {
        self.max_historical_versions
    }
}

impl Default for Config {
    fn default() -> Self {
        let max_historical_versions = 10;
        Self { max_historical_versions }
    }
}

// ENTRIES ITERATOR
// ================================================================================================

/// An iterator over the entries of an arbitrary tree in the forest.
#[allow(dead_code)] // Temporarily
pub enum EntriesIterator<'forest, B: Backend> {
    /// An iterator over a tree in the forest that is formed from a merger of the full tree and a
    /// historical overlay.
    WithHistory {
        /// A reference to the forest that contains the tree over which this iterator is defined.
        forest: &'forest LargeSmtForest<B>,

        /// The iterator over the entries in the full tree.
        full_tree_iter: Box<dyn Iterator<Item = TreeEntry> + 'forest>,

        /// The iterator over the entries in the history.
        history_entries_iter: Box<dyn Iterator<Item = (Word, Word)> + 'forest>,
    },

    /// An iterator over a tree in the forest that is simply an iterator over the full tree.
    WithoutHistory {
        /// A reference to the forest that contains the tree over which this iterator is defined.
        forest: &'forest LargeSmtForest<B>,

        /// The iterator over the entries in the full tree.
        full_tree_iter: Box<dyn Iterator<Item = TreeEntry> + 'forest>,
    },
}

#[allow(dead_code)] // Temporarily
impl<'forest, B: Backend> EntriesIterator<'forest, B> {
    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest` without associated history.
    ///
    /// Note that it _does not_ perform checks as to the existence of `tree` in the forest for
    /// performance reasons. This must be checked _prior_ to the construction of the iterator.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend could not be queried for the tree data.
    ///
    /// # Panics
    ///
    /// - If `tree` does not exist in `forest`.
    fn new_with_history(_forest: &'forest LargeSmtForest<B>, _tree: TreeId) -> Result<Self> {
        todo!("LargeSmtForest::new_with_history")
    }

    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest` without any associated history.
    ///
    /// Note that it _does not_ perform checks as to the existence of `tree` in the forest for
    /// performance reasons. This must be checked _prior_ to the construction of the iterator.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend could not be queried for the tree data.
    ///
    /// # Panics
    ///
    /// - If `tree` does not exist in `forest`.
    fn new_without_history(forest: &'forest LargeSmtForest<B>, tree: TreeId) -> Result<Self> {
        Ok(Self::WithoutHistory {
            forest,
            full_tree_iter: Box::new(forest.backend.entries(tree.lineage())?),
        })
    }
}

#[allow(dead_code)] // Temporarily
impl<B: Backend> Iterator for EntriesIterator<'_, B> {
    type Item = TreeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO this needs to construct an iterator that yields the _merger_ of entries from the
        //   full tree and the overlays.
        //
        // - The complexity arises from the fact that the overlays can _remove_ items, not just
        //   replace them.
        // - This means that it is not sufficient to query the overlay for every entry in the
        //   concrete tree's iterator, and instead has to rely on some merging and sorting logic.

        todo!()
    }
}
