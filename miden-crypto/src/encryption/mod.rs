use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    Felt,
    utils::{Deserializable, Serializable},
};

pub mod rpo;

pub mod xchacha;

// CONSTANTS
// ================================================================================================

/// Number of bytes to pack into one field element
const BINARY_CHUNK_SIZE: usize = 7;

// TRAITS
// ================================================================================================

/// Authenticated encryption with associated data (AEAD) scheme
pub trait AeadMiden {
    type Key: Zeroize;
    type Nonce: Clone + Serializable + Deserializable;

    /// Derive an encryption key from shared secret and salt using KDF
    fn derive_key(shared_secret: &[u8], salt: &[u8]) -> Self::Key;

    /// Generate a random nonce
    fn generate_nonce<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Nonce;

    /// Encrypt plaintext, as Felt-s, with associated data
    fn encrypt(
        key: &Self::Key,
        nonce: Self::Nonce,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IesError>;

    /// Decrypt ciphertext, as Felt-s, with associated data
    fn decrypt(
        key: &Self::Key,
        nonce: Self::Nonce,
        ciphertext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IesError>;

    /// Encrypt plaintext, as bytes, with associated data
    fn encrypt_bytes(
        key: &Self::Key,
        nonce: Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IesError>;

    /// Decrypt ciphertext, as bytes, with associated data
    fn decrypt_bytes(
        key: &Self::Key,
        nonce: Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IesError>;
}

// ERROR TYPES
// ================================================================================================

#[derive(Debug, Error)]
pub enum IesError {
    #[error("key agreement failed")]
    KeyAgreementFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid key size failed")]
    InvalidKeySize,
    #[error("invalid nonce size failed")]
    InvalidNonceSize,
}

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
