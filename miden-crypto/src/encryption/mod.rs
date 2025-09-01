//! AEAD (authenticated encryption with associated data) schemes.

use thiserror::Error;

pub mod aead_rpo;

pub mod xchacha;

// CONSTANTS
// ================================================================================================

/// Number of bytes to pack into one field element
const BINARY_CHUNK_SIZE: usize = 7;

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// Authentication tag verification failed
    #[error("authentication tag verification failed")]
    InvalidAuthTag,
    /// Operation failed
    #[error("operation failed")]
    FailedOperation,
}
