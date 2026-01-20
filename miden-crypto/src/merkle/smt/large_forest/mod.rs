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

mod backend;
mod error;
mod history;
mod operation;
mod property_tests;
mod root;
mod tests;

use core::iter::once;

pub use backend::{Backend, BackendError};
pub use error::{LargeSmtForestError, Result};
pub use operation::{ForestOperation, SmtForestUpdateBatch, SmtUpdateBatch};
pub use root::{RootInfo, TreeId, VersionId};

use crate::{
    Map, Set, Word,
    merkle::smt::{
        SmtProof,
        large_forest::{
            history::History,
            root::{LineageId, RootValue, TreeWithRoot, UniqueRoot},
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
    /// Constructs a new forest backed by the provided `backend`.
    ///
    /// The constructor will treat whatever state is contained within the provided `backend` as the
    /// starting state for the forest. This means that, if you pass a newly-initialized storage, the
    /// forest will start in an empty state. Similarly, if you pass a `backend` that already
    /// contains some data (loaded from disk, for example), then the forest will start in that state
    /// instead.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Other`] if the forest cannot be started up correctly using the
    ///   provided `backend`.
    pub fn new(_backend: B) -> Result<Self> {
        todo!("LargeSmtForest::new")
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
    /// Returns an iterator that yields the (uniquely identified) root of the latest tree in each
    /// lineage contained in the forest.
    ///
    /// The iteration order is unspecified.
    pub fn current_roots(&self) -> impl Iterator<Item = UniqueRoot> {
        self.lineage_data.iter().map(|(l, d)| UniqueRoot::new(*l, d.latest_root))
    }

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

    /// Returns an iterator that yields the historical root values for trees within the specified
    /// `lineage`, or [`None`] if the lineage is not known.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present. It does _not_ include the latest root in
    /// the specified `lineage`.
    pub fn historical_roots(&self, lineage: LineageId) -> Option<impl Iterator<Item = RootValue>> {
        // We skip the first element as this is always guaranteed to be the current root for the
        // lineage.
        self.lineage_roots(lineage).map(|i| i.skip(1))
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
    /// Returns an opening for the specified `key` in the specified `tree`, or [`None`] if there is
    /// no value corresponding to the provided `key` in that tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    /// - [`LargeSmtForestError::MerkleError`] If there is insufficient data in the specified `tree`
    ///   to provide an opening for `key`.
    pub fn open(&self, _tree: TreeId, _key: Word) -> Result<Option<SmtProof>> {
        todo!("LargeSmtForest::open")
    }

    /// Returns the value associated with the provided `key` in the specified `tree`, or [`None`] if
    /// there is no value corresponding to the provided `key` in that tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] If the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn get(&self, _root: TreeId, _key: Word) -> Result<Option<Word>> {
        todo!("LargeSmtForest::get")
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
    /// Performs the provided `updates` on the latest tree in the specified `lineage`, adding a
    /// single new root to the forest (corresponding to `new_version`) for the entire batch, and
    /// returning the data for the new root of the tree.
    ///
    /// If applying the provided `operations` results in no changes to the tree, then the root data
    /// will be returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] If the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    pub fn update_tree(
        &mut self,
        _lineage: LineageId,
        _new_version: VersionId,
        _updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        todo!("LargeSmtForest::modify_tree")
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
