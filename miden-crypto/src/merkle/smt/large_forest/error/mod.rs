//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

pub mod subtree;

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::large_forest::{history::error::HistoryError, storage},
};

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    #[error(transparent)]
    HistoryError(#[from] HistoryError),

    #[error(transparent)]
    MerkleError(#[from] MerkleError),

    #[error(transparent)]
    StorageError(#[from] storage::StorageError),
}

/// The result type for use within the large SMT forest portion of the library.
#[allow(dead_code)] // Temporary
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;
