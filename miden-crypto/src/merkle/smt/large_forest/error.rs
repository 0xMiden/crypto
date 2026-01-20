//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::boxed::Box;

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::{
        TreeId, VersionId,
        large_forest::{backend::BackendError, history::error::HistoryError, root::LineageId},
    },
};

// LARGE SMT FOREST ERROR
// ================================================================================================

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    /// Errors in the history subsystem of the forest.
    #[error(transparent)]
    HistoryError(#[from] HistoryError),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    MerkleError(#[from] MerkleError),

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
            BackendError::Merkle(e) => LargeSmtForestError::from(e),
            BackendError::Other(e) => LargeSmtForestError::from(e),
        }
    }
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;
