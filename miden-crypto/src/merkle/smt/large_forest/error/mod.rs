//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

pub mod subtree;

use thiserror::Error;

use crate::{
    Word,
    merkle::{
        MerkleError,
        smt::large_forest::{error::prefix::PrefixError, history::error::HistoryError, storage},
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

    /// Errors with the storage backend of the forest.
    #[error(transparent)]
    StorageError(#[from] storage::StorageError),

    /// Errors with the in-memory tree prefixes in the forest.
    #[error(transparent)]
    PrefixError(#[from] PrefixError),

    /// Raised when an attempt is made to modify a frozen tree.
    #[error("Attempted to modify frozen tree with root {0}")]
    InvalidModification(Word),
}

/// The result type for use within the large SMT forest portion of the library.
#[allow(dead_code)] // Temporary
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;

pub mod prefix {
    use thiserror::Error;

    use crate::{Word, merkle::smt::large_forest::utils::LinearIndex};

    #[derive(Debug, Eq, Error, PartialEq)]
    pub enum PrefixError {
        /// Raised if an indexing operation would be out of bounds.
        #[error("Index {0} was out of bounds in a prefix with {1} levels")]
        IndexOutOfBounds(LinearIndex, u8),

        /// Raised if the forest cannot restore correctly from the saved restoration data.
        #[error("Restoration data for tree with root {0} produced root {1}")]
        InvalidRestoration(Word, Word),

        /// Raised if the number of leaves in the restoration data provided to the prefix is
        /// incorrect for the depth of the prefix.
        #[error("Was given {0} leaves but expected {1}")]
        WrongLeafCount(u64, u64),
    }

    /// The result type for use within the prefix portion of the library.
    #[allow(dead_code)] // Temporary
    pub type Result<T> = core::result::Result<T, PrefixError>;
}
