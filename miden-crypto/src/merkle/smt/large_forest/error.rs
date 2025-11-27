//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use thiserror::Error;

use crate::merkle::MerkleError;

/// The errors returned by operations on the large SMT forest.
///
/// This type primarily serves to wrap more specific error types from various subsystems into a
/// generic interface type.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    #[error(transparent)]
    HistoryError(#[from] history::HistoryError),

    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

pub mod history {
    use thiserror::Error;

    use crate::Word;

    /// The type of errors returned by the history subsystem of the large SMT forest.
    #[derive(Debug, Error, PartialEq)]
    pub enum HistoryError {
        #[error("The root {0} had no corresponding history version")]
        NoSuchVersion(Word),

        #[error("The history contains no deltas")]
        NothingToRemove,
    }

    /// The result type for use within the history subsystem of the large SMT forest.
    pub type Result<T> = std::result::Result<T, HistoryError>;
}
