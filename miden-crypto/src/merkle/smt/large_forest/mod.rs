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
//! # Data Storage
//!
//! The SMT forest is parametrised over the [`Backend`] implementation that it uses. These backends
//! may have significantly varied performance characteristics, and hence any performance analysis of
//! the forest should be done in conjunction with a specific backend. The forest itself takes pains
//! to not make any assumptions about properties of the backend in use.
//!
//! Take care to read the documentation of the specific [`Backend`] that you are planning to use in
//! order to understand its performance, gotchas, and other such details.

mod backend;
mod error;
pub mod history;
pub mod operation;
mod prefix;
pub mod root;
pub mod utils;

pub use backend::Backend;
pub use error::{LargeSmtForestError, Result};
pub use utils::SubtreeLevels;

use crate::{
    Map, Set, Word,
    merkle::{
        EmptySubtreeRoots, MerkleError,
        smt::{
            SMT_DEPTH, SmtProof,
            large_forest::{
                history::{History, VersionId},
                operation::{SmtForestUpdateBatch, SmtUpdateBatch},
                root::RootInfo,
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
    histories: Map<Word, History>,
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
    /// - [`LargeSmtForestError::BackendError`] if the forest cannot be started up correctly using
    ///   the provided `backend`.
    pub fn new(_backend: B) -> Result<Self, B::Error> {
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
    /// Returns a set of all the roots that the forest knows about, including those from all
    /// historical versions.
    pub fn roots(&self) -> Set<Word> {
        let mut roots: Set<Word> = self.histories.keys().cloned().collect();
        self.histories.values().for_each(|h| roots.extend(h.roots()));
        roots.insert(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));
        roots
    }

    /// Returns the number of trees in the forest that have unique identity.
    ///
    /// This is **not** the number of unique tree lineages in the forest, as it includes all
    /// historical trees as well. For that, see [`Self::lineage_count`].
    pub fn tree_count(&self) -> usize {
        self.roots().len()
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
    pub fn is_latest_version(&self, root: Word) -> bool {
        self.histories.contains_key(&root) || *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root
    }

    /// Returns data describing what information the forest knows about the provided `root`.
    pub fn knows_root(&self, root: Word) -> RootInfo {
        if self.histories.contains_key(&root) {
            RootInfo::LatestVersion
        } else if let Some(h) = self.histories.get(&root)
            && h.is_known_root(root)
        {
            RootInfo::HistoricalVersion
        } else if root == *EmptySubtreeRoots::entry(SMT_DEPTH, 0) {
            RootInfo::EmptyTree
        } else {
            RootInfo::Missing
        }
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
    /// Returns an opening for the specified `key` in the SMT with the specified `root`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BackendError`] if an error occurs when trying to query the backend.
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest, or if the forest does not contain sufficient data to provide an opening for `key`.
    pub fn open(&self, _root: Word, _key: Word) -> Result<SmtProof, B::Error> {
        todo!("LargeSmtForest::open")
    }

    /// Returns the value associated with the provided `key` in the SMT with the provided `root`, or
    /// [`None`] if no such value exists.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BackendError`] if an error occurs when trying to query the backend.
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest, or if the forest does not contain sufficient data to get the value for `key`.
    pub fn get(&self, _root: Word, _key: Word) -> Result<Option<Word>, B::Error> {
        todo!("LargeSmtForest::get")
    }

    /// Returns an iterator over the historical roots in the forest belonging to the lineage with
    /// the provided `current_root`.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest.
    pub fn historical_roots(
        &self,
        current_root: Word,
    ) -> Result<impl Iterator<Item = Word>, B::Error> {
        self.histories
            .get(&current_root)
            .map(|h| h.roots())
            .ok_or(MerkleError::RootNotInStore(current_root).into())
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
    /// Performs the provided `operations` on the tree with the provided `root`, adding a single new
    /// root to the forest for the entire batch and returning that root.
    ///
    /// If applying the provided `operations` results in no changes to the tree, then `root` will be
    /// returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BackendError`] if an error occurs when trying to access the
    ///   backend.
    /// - [`LargeSmtForestError::InvalidModification`] if `root` corresponds to a tree that is not
    ///   the latest in its lineage.
    /// - [`LargeSmtForestError::MerkleError`] if `root` is not a root known by the forest.
    pub fn modify_tree(
        &mut self,
        _root: Word,
        _new_version: VersionId,
        _operations: SmtUpdateBatch,
    ) -> Result<Word, B::Error> {
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
    /// Performs the provided `operations` on the forest, adding at most one new root to the forest
    /// for each target root in `operations` and returning a mapping from old root to new root.
    ///
    /// If applying the associated batch to any given lineage in the forest results in no changes to
    /// that tree, the initial root for that lineage will be returned and no new tree will be
    /// allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BackendError`] if an error occurs when trying to access the
    ///   backend.
    /// - [`LargeSmtForestError::InvalidModification`] if any root in the batch corresponds to a
    ///   tree that is not the latest in its lineage.
    /// - [`LargeSmtForestError::MerkleError`] if any root in the batch is not a root known by the
    ///   forest.
    pub fn modify_forest(
        &mut self,
        _operations: SmtForestUpdateBatch,
    ) -> Result<Map<Word, Word>, B::Error> {
        todo!("LargeSmtForest::modify_forest")
    }

    /// Removes all tree versions in the forest that are older than the provided `version`.
    ///
    /// In the case that the current version of a given tree in the forest is older than `version`,
    /// that current version is retained.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BackendError`] if the backend cannot be accessed to get the full
    ///   tree versions.
    ///
    /// # Panics
    ///
    /// - If there is no history that corresponds to one of the trees that is fully stored.
    pub fn truncate(&mut self, version: VersionId) -> Result<(), B::Error> {
        // We start by clearing any history for which the `version` corresponds to the latest
        // version and hence the full tree.
        self.backend.versions()?.for_each(|(root, v)| {
            if v == version {
                self.histories
                    .get_mut(&root)
                    .expect(
                        "A full tree did not have a corresponding history, but is required
        to",
                    )
                    .clear();
            }
        });

        // Then we just run through all the histories and truncate them to this version if needed,
        // which provides the correct behaviour.
        self.histories.values_mut().for_each(|h| {
            h.truncate(version);
        });

        Ok(())
    }
}
