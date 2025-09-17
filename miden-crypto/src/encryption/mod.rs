//! AEAD (authenticated encryption with associated data) schemes.

use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::utils::{Deserializable, Serializable};

pub mod xchacha;

pub mod ies;

// AEAD TRAIT
// ================================================================================================

/// Authenticated encryption with associated data (AEAD) scheme
pub trait AeadScheme {
    const KEY_SIZE: usize;

    type Key: Deserializable + Zeroize;
    type Nonce: Clone + Serializable + Deserializable;

    fn key_from_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError>;

    fn generate_nonce<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Nonce;

    fn encrypt_bytes(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    fn decrypt_bytes(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug)]
pub enum EncryptionError {
    /// Authentication tag verification failed
    InvalidAuthTag,
    /// Operation failed
    FailedOperation,
    /// Padding malformed
    MalformedPadding,
    /// Nonce is invalid
    InvalidNonce,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InvalidAuthTag => write!(f, "authentication tag verification failed"),
            EncryptionError::FailedOperation => write!(f, "operation failed"),
            EncryptionError::MalformedPadding => write!(f, "malformed padding"),
            EncryptionError::InvalidNonce => write!(f, "nonce provided is invalid"),
        }
    }
}

impl core::error::Error for EncryptionError {}
