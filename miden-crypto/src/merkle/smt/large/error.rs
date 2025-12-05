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

#[cfg(test)]
// Compile-time assertion that LargeSmtError implements the required traits
const _: fn() = || {
    fn assert_impl<T: std::error::Error + Send + Sync + 'static>() {}
    assert_impl::<LargeSmtError>();
    assert_impl::<MerkleError>();
    assert_impl::<StorageError>();
};
