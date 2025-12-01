//! Errors in working with subtrees.

use thiserror::Error;

/// Errors raised when encountering an issue when working with subtrees.
#[derive(Debug, Error)]
pub enum SubtreeError {
    /// Raised when decoding the subtree from bytes and encountering insufficient node data.
    #[error("Expected {expected} bytes of node data, found {found} bytes")]
    BadHashLen { expected: usize, found: usize },

    /// Raised when the left index has an invalid hash.
    #[error("Invalid left hash format at local index {index}")]
    BadLeft { index: u64 },

    /// Raised when the left index has an invalid hash.
    #[error("Invalid right hash format at local index {index}")]
    BadRight { index: u64 },

    /// When extra node data exists in the bytestream after the expected data.
    #[error("Found extra node data after bitmask-indicated entries")]
    ExtraData,

    /// When the node data for the left index of a node.
    #[error("Missing left node data at local index {index}")]
    MissingLeft { index: u64 },

    /// When the node data for the right index of a node.
    #[error("Missing right node data at local index {index}")]
    MissingRight { index: u64 },

    /// Raised when there is insufficient data when decoding the subtree.
    #[error("Found {found} bytes when decoding the subtree, but need at least {min} bytes")]
    TooShort { found: usize, min: usize },
}
