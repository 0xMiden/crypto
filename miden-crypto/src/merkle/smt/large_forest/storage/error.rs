//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::{boxed::Box, string::String};

use thiserror::Error;

use crate::{
    Word,
    merkle::smt::{SmtLeafError, large_forest::error::subtree::SubtreeError},
};

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum StorageError {
    /// An error coming directly from a malfunction in the storage backend.
    #[error(transparent)]
    Backend(#[from] Box<dyn core::error::Error + Send + 'static>),

    /// An error with the contents of a compact tree leaf.
    #[error(transparent)]
    Leaf(#[from] SmtLeafError),

    /// Raised when a storage backend does not support multiple concurrent transactions.
    #[error("This backend does not support multiple concurrent transactions")]
    MultipleTransactionsUnsupported,

    /// Raised when an entity is requested from the storage but is not managed by this storage due
    /// to being part of the guaranteed-to-be-in-memory storage.
    #[error("The entity {0} is not part of this storage")]
    NotInStorage(String),

    /// Issued if an operation that can only be performed with an active transaction is performed
    /// outside a transaction.
    #[error("An operation was issued that requires a transaction to have been started.")]
    NotInTransaction,

    /// An error when reading from or writing to a subtree in storage.
    #[error(transparent)]
    Subtree(#[from] SubtreeError),

    /// Raised when the storage does not store a tree with the provided root.
    #[error("No tree with root {0} exists in this storage")]
    UnknownRoot(Word),

    /// Raised when a storage implementation is given a transaction handle that it did not allocate.
    #[error("A transaction handle was provided that was not issued by this storage")]
    UnknownTransaction,

    /// The requested operation is not supported by this backend.
    ///
    /// In some cases it may be possible to fall back to a more complex slow path when this error is
    /// received.
    #[error("The operation {0} is not supported")]
    UnsupportedOperation(String),
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = core::result::Result<T, StorageError>;
