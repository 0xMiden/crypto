//! AEAD (authenticated encryption with associated data) schemes.

use core::fmt;

pub mod xchacha;

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug)]
pub enum EncryptionError {
    /// Authentication tag verification failed
    InvalidAuthTag,
    /// Operation failed
    FailedOperation,
    MalformedPadding,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InvalidAuthTag => write!(f, "authentication tag verification failed"),
            EncryptionError::FailedOperation => write!(f, "operation failed"),
            EncryptionError::MalformedPadding => write!(f, "malformed padding"),
        }
    }
}

impl core::error::Error for EncryptionError {}
