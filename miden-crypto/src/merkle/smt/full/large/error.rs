use thiserror::Error;

use super::{MerkleError, StorageError};

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during LargeSmt operations.
#[derive(Debug, Error)]
pub enum LargeSmtError {
    /// A Merkle tree operation failed.
    #[error("merkle operation failed")]
    Merkle(#[from] MerkleError),

    /// A storage operation failed.
    #[error("storage operation failed")]
    Storage(#[from] StorageError),
}
