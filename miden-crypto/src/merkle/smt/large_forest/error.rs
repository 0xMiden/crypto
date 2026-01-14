//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::boxed::Box;

use thiserror::Error;

use crate::{
    Word,
    merkle::{
        MerkleError,
        smt::large_forest::{backend::BackendError, history::error::HistoryError},
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
    InvalidModification(Word),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    MerkleError(#[from] MerkleError),

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
