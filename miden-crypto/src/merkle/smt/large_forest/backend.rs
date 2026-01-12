//! This file contains the [`Backend`] trait for the [`LargeSmtForest`] implementation and the
//! supporting types it needs.

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;

use thiserror::Error;

use crate::{
    Word,
    merkle::{
        MerkleError,
        smt::{
            SmtProof,
            full::SMT_DEPTH,
            large_forest::{
                history::VersionId,
                operation::{SmtForestUpdateBatch, SmtUpdateBatch},
            },
        },
    },
};
// TYPE ALIASES
// ================================================================================================

/// The mutation set used by the forest backends.
///
/// At the moment this is used for _reverse_ mutations that "undo" the changes made to the tree(s),
/// but may be harmonised with [`SmtUpdateBatch`] in the future. For more information on its use for
/// reverse mutations, see [`crate::merkle::smt::SparseMerkleTree::apply_mutations_with_reversion`].
pub type MutationSet = crate::merkle::smt::MutationSet<SMT_DEPTH, Word, Word>;

// BACKEND
// ================================================================================================

/// The backing storage for the SMT forest, providing the necessary high-level methods for
/// performing operations on the full trees that make up the forest, while allowing the forest
/// itself to be storage agnostic.
///
/// # Backend Data Storage
///
/// Having a generic [`Backend`] provides no guarantees to the user about how it stores data and
/// what patterns are used for data access under the hood. It is, however, guaranteed to store
/// _only_ the data necessary to describe the latest state of each tree in the forest.
pub trait Backend
where
    Self: Debug,
{
    // QUERIES
    // ============================================================================================

    /// Returns an opening for the specified `key` in the SMT with the specified `root`.
    fn open(&self, root: Word, key: Word) -> Result<SmtProof>;

    /// Returns the value associated with the provided `key` in the SMT with the provided `root`, or
    /// [`None`] if no such value exists.
    fn get(&self, root: Word, key: Word) -> Result<Option<Word>>;

    /// Returns the version of the tree with the provided `root`.
    fn version(&self, root: Word) -> Result<VersionId>;

    /// Returns an iterator over all the tree roots and versions that the backend knows about.
    ///
    /// The iteration order is unspecified.
    fn versions(&self) -> Result<impl Iterator<Item = (Word, VersionId)>>;

    // SINGLE-TREE MODIFIERS
    // ============================================================================================

    /// Performs the provided `updates` on the tree with the provided `root`, returning the new
    /// root.
    ///
    /// Implementations must guarantee the following behavior, with non-conforming implementations
    /// considered to be a bug:
    ///
    /// - At most one new root must be added to the forest for the entire batch.
    /// - If applying the provided `updates` results in no changes to the tree, no new tree must be
    ///   allocated.
    fn update_tree(
        &mut self,
        root: Word,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet>;

    // MULTI-TREE MODIFIERS
    // ============================================================================================

    /// Performs the provided `updates` on the forest, setting all new tree states to have the
    /// provided `new_version` and returning a vector of the mutation sets that reverse the changes
    /// to each changed tree.
    ///
    /// Implementations must guarantee the following behaviour, with non-conforming implementations
    /// considered to be a bug:
    ///
    /// - At most one new root must be added to the forest for each target root in the provided
    ///   `updates`.
    /// - If applying the provided `updates` results in no changes to a given lineage of trees in
    ///   the forest, then no new tree must be allocated in that lineage.
    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<MutationSet>>;
}

// BACKEND ERROR
// ================================================================================================

/// The error type for use within Backends.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Raised when there is an error with the merkle tree semantics within the backend.
    #[error(transparent)]
    Merkle(#[from] MerkleError),

    /// Raised for arbitrary other errors within the backend.
    #[error(transparent)]
    Other(#[from] Box<dyn core::error::Error + Sync + Send>),
}

/// The result type for use with backends.
pub type Result<T> = core::result::Result<T, BackendError>;
