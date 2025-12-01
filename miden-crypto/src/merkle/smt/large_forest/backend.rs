//! This file contains the [`Backend`] trait for the [`LargeSmtForest`] implementation and the
//! supporting types it needs.

use core::{any::Any, error::Error, fmt::Debug};

use crate::{
    Map, Word,
    merkle::smt::{
        SmtProof,
        large_forest::{
            history::VersionId,
            operation::{SmtForestUpdateBatch, SmtUpdateBatch},
        },
    },
};

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
///
/// # Errors
///
/// The trait allows each implementation to provide its own error type as [`Self::Error`]. This
/// ensures that each backend can tailor its errors to its operation without having to worry about
/// using a pre-defined error enum. Every method is made to return this error type by default to
/// enable accurate error handling, but not all implementations may need to return an error in all
/// cases.
///
/// As a result, specific errors cannot be documented in the trait method documentation blocks and
/// so are not.
pub trait Backend
where
    Self: Debug,
{
    /// The error type used by the backend.
    type Error: BackendError;

    // QUERIES
    // ============================================================================================

    /// Returns an opening for the specified `key` in the SMT with the specified `root`.
    fn open(&self, root: Word, key: Word) -> Result<SmtProof, Self::Error>;

    /// Returns the value associated with the provided `key` in the SMT with the provided `root`, or
    /// [`None`] if no such value exists.
    fn get(&self, root: Word, key: Word) -> Result<Option<Word>, Self::Error>;

    /// Returns the version of the tree with the provided `root`.
    fn version(&self, root: Word) -> Result<VersionId, Self::Error>;

    /// Returns an iterator over all the tree roots and versions that the backend knows about.
    ///
    /// The iteration order is unspecified.
    fn versions(&self) -> Result<impl Iterator<Item = (Word, VersionId)>, Self::Error>;

    // SINGLE-TREE MODIFIERS
    // ============================================================================================

    /// Performs the provided `operations` on the tree with the provided `root`, returning the new
    /// root.
    ///
    /// Implementations must guarantee the following behavior, with non-conforming implementations
    /// considered to be a bug:
    ///
    /// - At most one new root must be added to the forest for the entire batch.
    /// - If applying the provided `operations` results in no changes to the tree, no new tree must
    ///   be allocated.
    fn modify_tree(
        &mut self,
        root: Word,
        new_version: VersionId,
        operations: SmtUpdateBatch,
    ) -> Result<Word, Self::Error>;

    // MULTI-TREE MODIFIERS
    // ============================================================================================

    /// Performs the provided `operations` on the forest, returning a mapping from old root to new
    /// root.
    ///
    /// Implementations must guarantee the following behaviour, with non-conforming implementations
    /// considered to be a bug:
    ///
    /// - At most one new root must be added to the forest for each target root in the provided
    ///   `operations`.
    /// - If applying the provided `operations` results in no changes to a given lineage of trees in
    ///   the forest, then no new tree must be allocated in that lineage.
    fn modify_forest(
        &mut self,
        operations: SmtForestUpdateBatch,
    ) -> Result<Map<Word, Word>, Self::Error>;
}

// BACKEND ERROR
// ================================================================================================

/// A trait that must be implemented by the error types for the [`Backend`], primarily serving to
/// work around the lack of negative impl constraints in Rust.
pub trait BackendError
where
    Self: Any + Debug + Error,
{
}
