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
//! This is done by identifying trees using the [`Root`], which combines the tree's root value with
//! a user-provided identifier that tags the tree with a 'domain'. This allows distinguishing
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

pub use backend::{Backend, BackendError};
pub use error::{LargeSmtForestError, Result};
pub use operation::{ForestOperation, SmtForestUpdateBatch, SmtUpdateBatch};
pub use root::{Root, RootInfo, VersionId};

use crate::{
    Map, Set, Word,
    merkle::{
        EmptySubtreeRoots, MerkleError,
        smt::{
            SMT_DEPTH, SmtProof,
            large_forest::{history::History, root::RootValue},
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
/// If an attempt is made to modify a frozen tree, the method in question will yield an
/// [`LargeSmtForestError::InvalidModification`] error as doing so represents a programmer bug.
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

    /// The container for the historical versions of each tree stored in the forest, identified by
    /// the _current root_ of that tree.
    ///
    /// This should contain an entry for every tree lineage contained in the forest, under the root
    /// of its current tree version.
    histories: Map<Root, History>,

    /// A set tracking which lineage histories in `histories` contain actual deltas in order to
    /// speed up querying.
    ///
    /// It must always be maintained as a strict subset of `histories.keys()`.
    non_empty_histories: Set<Root>,
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

/// These methods provide the ability to perform basic queries on the forest without the need to
/// access the underlying tree storage.
///
/// # Performance
///
/// All of these methods can be performed fully in-memory, and hence their performance is
/// predictable on a given machine regardless of the choice of [`Backend`] instance being used by
/// the forest.
impl<B: Backend> LargeSmtForest<B> {
    /// Returns an iterator over all roots that the forest knows about, including those from all
    /// historical versions.
    ///
    /// The iteration order of the roots is unspecified.
    pub fn roots(&self) -> impl Iterator<Item = Root> {
        // As the history container does not deal in roots with domains, we have to attach the
        // corresponding domain to each root, and do this as lazily as possible to avoid
        // materializing more things than we need to.
        self.histories.keys().cloned().chain(
            self.histories
                .iter()
                .flat_map(|(k, v)| v.roots().map(|r| Root::new(k.lineage(), r))),
        )
    }

    /// Returns an iterator over the roots for the latest version of every tree in the forest.
    ///
    /// The iteration order is unspecified.
    pub fn current_roots(&self) -> impl Iterator<Item = Root> {
        self.histories.keys().cloned()
    }

    /// Returns an iterator over the historical roots in the forest belonging to the lineage with
    /// the provided `current_root`.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present. It does _not_ include the specified
    /// `current_root`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest.
    pub fn historical_roots(&self, current_root: Root) -> Result<impl Iterator<Item = RootValue>> {
        self.histories
            .get(&current_root)
            .map(|h| h.roots())
            .ok_or(MerkleError::RootNotInStore(current_root.value()).into())
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
        self.histories.iter().len()
    }

    /// Returns `true` if the provided `root` points to a tree that is the latest version, and
    /// `false` otherwise.
    ///
    /// A tree being the latest version is one that can be modified to yield a new version. In other
    /// words it does not represent a historical tree version.
    pub fn is_latest_version(&self, root: Root) -> bool {
        self.histories.contains_key(&root)
            || *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root.value()
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
    /// Returns an opening for the specified `key` in the SMT with the specified `root`, or [`None`]
    /// if there is no tree with the specified `root` in the forest.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest, or if the forest does not contain sufficient data to provide an opening for `key`.
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn open(&self, _root: Root, _key: Word) -> Result<Option<SmtProof>> {
        todo!("LargeSmtForest::open")
    }

    /// Returns the value associated with the provided `key` in the SMT with the provided `root`, or
    /// [`None`] if no such value exists.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest, or if the forest does not contain sufficient data to get the value for `key`.
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn get(&self, _root: Root, _key: Word) -> Result<Option<Word>> {
        todo!("LargeSmtForest::get")
    }

    /// Returns data describing what information the forest knows about the provided `root`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn knows_root(&self, root: Root) -> Result<RootInfo> {
        if self.histories.contains_key(&root) {
            Ok(RootInfo::LatestVersion(self.backend.version(root)?))
        } else if let Some(v) = self.histories.iter().find_map(|(r, h)| {
            if r.lineage() == root.lineage() {
                h.version(root.value())
            } else {
                None
            }
        }) {
            Ok(RootInfo::HistoricalVersion(v))
        } else if root.value() == *EmptySubtreeRoots::entry(SMT_DEPTH, 0) {
            Ok(RootInfo::EmptyTree)
        } else {
            Ok(RootInfo::Missing)
        }
    }

    /// Gets the version associated with the provided root, or returns [`None`] if the root is
    /// unknown to the forest.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn version(&self, root: Root) -> Result<Option<VersionId>> {
        Ok(match self.knows_root(root)? {
            RootInfo::LatestVersion(v) | RootInfo::HistoricalVersion(v) => Some(v),
            RootInfo::EmptyTree | RootInfo::Missing => None,
        })
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
    /// Performs the provided `updates` on the tree with the provided `root`, adding a single new
    /// root to the forest (corresponding to `new_version`) for the entire batch and returning that
    /// root.
    ///
    /// If applying the provided `operations` results in no changes to the tree, then `root` will be
    /// returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::InvalidModification`] if `root` corresponds to a tree that is not
    ///   the latest in its lineage.
    /// - [`LargeSmtForestError::MerkleError`] if `root` is not a root known by the forest.
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn update_tree(
        &mut self,
        _root: Root,
        _new_version: VersionId,
        _updates: SmtUpdateBatch,
    ) -> Result<Root> {
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
    /// from old root to new root.
    ///
    /// If applying the associated batch to any given lineage in the forest results in no changes to
    /// that tree, the initial root for that lineage will be returned and no new tree will be
    /// allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::InvalidModification`] if any root in the batch corresponds to a
    ///   tree that is not the latest in its lineage.
    /// - [`LargeSmtForestError::MerkleError`] if any root in the batch is not a root known by the
    ///   forest.
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    pub fn update_forest(
        &mut self,
        _new_version: VersionId,
        _updates: SmtForestUpdateBatch,
    ) -> Result<Map<Root, Root>> {
        todo!("LargeSmtForest::modify_forest")
    }

    /// Removes all tree versions in the forest that are older than the provided `version`.
    ///
    /// In the case that the current version of a given tree in the forest is older than `version`,
    /// that current version is retained.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Other`] if the backend cannot be accessed to get the full tree
    ///   versions.
    /// - [`LargeSmtForestError`] if the backend returns an error as part of the query.
    ///
    /// # Panics
    ///
    /// - If there is no history that corresponds to one of the trees that is fully stored.
    pub fn truncate(&mut self, version: VersionId) -> Result<()> {
        // Truncation in the history is defined such that it never removes a version that could
        // possibly serve as the latest delta for a newer version. This is because it cannot safely
        // know if a version `v` is between the latest delta `d` and the current version `c`, as it
        // has no knowledge of the current version.
        //
        // Thus, if we have a version `v` such that `d <= v < c`, we need to retain the reversion
        // delta `d` in the history to correctly service queries for `v`. If, however, we have `d <
        // c <= v` we need to explicitly remove the last delta as well.
        //
        // To that end, we handle the latter case first, by explicitly calling `History::clear()`.
        self.backend.versions()?.for_each(|(root, v)| {
            if version >= v {
                self.histories
                    .get_mut(&root)
                    .expect(
                        "A full tree did not have a corresponding history, but is required
        to",
                    )
                    .clear();
                self.non_empty_histories.remove(&root);
            }
        });

        // The other case is `v < c`, which is handled simply by the truncation mechanism in the
        // history as we want. In other words, it retains the necessary delta, and so we can just
        // call it here.
        self.non_empty_histories.iter().for_each(|h| {
            self.histories
                .get_mut(h)
                .expect("Histories did not contain an entry corresponding to a tree")
                .truncate(version);
        });

        Ok(())
    }
}
