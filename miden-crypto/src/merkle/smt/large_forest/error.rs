//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::boxed::Box;

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::{
        Root,
        large_forest::{backend::BackendError, history::error::HistoryError, root::RootValue},
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

    /// Raised when an attempt is made to modify a frozen tree.
    #[error("Attempted to modify non-current tree with root {0}")]
    InvalidModification(RootValue),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    MerkleError(#[from] MerkleError),

    /// Raised when an operation expects that a root is present but it is not.
    #[error("Root {0} is not present in the forest")]
    UnknownRoot(Root),

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
            BackendError::UnknownRoot(r) => LargeSmtForestError::UnknownRoot(r),
            BackendError::Other(e) => LargeSmtForestError::from(e),
        }
    }
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;
