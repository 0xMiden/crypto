//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::boxed::Box;

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::{
        SmtLeafError, TreeId, VersionId,
        large_forest::{backend::BackendError, history::error::HistoryError, root::LineageId},
    },
};
// LARGE SMT FOREST ERROR
// ================================================================================================

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    /// Raised when the provided version for any update is older than the latest-known version for
    /// the lineage being updated.
    #[error("Version {0} is not newer than latest-known {1}")]
    BadVersion(VersionId, VersionId),

    /// Raised when there is a conflict between an existing lineage ID and one already in the
    /// forest.
    #[error("Duplicate lineage ID {0} provided")]
    DuplicateLineage(LineageId),

    /// Raised for arbitrary errors that are not derived from user-input. These **must be considered
    /// fatal by the caller**, but exist to provide the caller with control over process termination
    /// (e.g. for improved diagnostics) wherever possible.
    #[error(transparent)]
    Fatal(Box<dyn core::error::Error + Sync + Send>),

    /// Errors in the history subsystem of the forest.
    #[error(transparent)]
    History(#[from] HistoryError),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    Merkle(#[from] MerkleError),

    /// Errors in working with leaves in the merkle trees.
    #[error(transparent)]
    SmtLeaf(#[from] SmtLeafError),

    /// Raised when an operation specifies a lineage that is not known.
    #[error("The lineage {0:?} is not in the forest")]
    UnknownLineage(LineageId),

    /// Raised when an operation specifies a tree that is not known.
    #[error("The tree")]
    UnknownTree(TreeId),

    /// Raised when an operation requests a version that is not known.
    #[error("The version {0} is not known by the forest")]
    UnknownVersion(VersionId),

    /// Raised for arbitrary other errors.
    #[error(transparent)]
    Other(#[from] Box<dyn core::error::Error + Sync + Send>),
}

/// We want to forward backend errors specifically when we can, so we manually implement the
/// conversion.
impl From<BackendError> for LargeSmtForestError {
    fn from(value: BackendError) -> Self {
        match value {
            BackendError::DuplicateLineage(l) => LargeSmtForestError::DuplicateLineage(l),
            BackendError::Internal(e) => LargeSmtForestError::Fatal(e),
            BackendError::Merkle(e) => LargeSmtForestError::from(e),
            BackendError::Other(e) => LargeSmtForestError::from(e),
            BackendError::UnknownLineage(t) => LargeSmtForestError::UnknownLineage(t),
        }
    }
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;
