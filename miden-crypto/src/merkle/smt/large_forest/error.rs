//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

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
pub enum LargeSmtForestError<E: BackendError> {
    /// Errors with the storage backend of the forest.
    #[error(transparent)]
    BackendError(#[from] E),

    /// Errors in the history subsystem of the forest.
    #[error(transparent)]
    HistoryError(#[from] HistoryError),

    /// Raised when an attempt is made to modify a frozen tree.
    #[error("Attempted to modify non-current tree with root {0}")]
    InvalidModification(Word),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T, B> = core::result::Result<T, LargeSmtForestError<B>>;
