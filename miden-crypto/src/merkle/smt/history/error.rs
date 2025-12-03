//! The error type and utility types for working with errors from the SMT history construct.
use thiserror::Error;

use crate::{Word, merkle::smt::history::VersionId};

/// The type of errors returned by the history container.
#[derive(Debug, Error, PartialEq)]
pub enum HistoryError {
    /// Raised when the queried version id is not found in the history.
    #[error("The version id {0} had no corresponding history version")]
    NoSuchId(VersionId),

    /// Raised when no version exists in the history for an arbitrary query.
    #[error("No such item matched the provided condition")]
    NoSuchVersion,

    /// Raised when the queried root is not found in the history.
    #[error("The root {0} had no corresponding history version")]
    NoSuchRoot(Word),

    /// Raised when a version is added to the history and is not newer than the previous.
    #[error("Version {0} is not monotonic with respect to {1}")]
    NonMonotonicVersions(VersionId, VersionId),
}

/// The result type for use within the history container.
pub type Result<T> = core::result::Result<T, HistoryError>;
