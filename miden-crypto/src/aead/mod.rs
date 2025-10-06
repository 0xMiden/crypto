//! AEAD (authenticated encryption with associated data) schemes.

use alloc::vec::Vec;
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Felt, utils::Deserializable};

pub mod aead_rpo;
pub mod xchacha;

/// Indicates whether encrypted data originated from field elements or raw bytes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Elements = 0,
    Bytes = 1,
}

impl TryFrom<u8> for DataType {
    type Error = InvalidDataTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DataType::Elements),
            1 => Ok(DataType::Bytes),
            _ => Err(InvalidDataTypeError { value }),
        }
    }
}

// AEAD TRAIT
// ================================================================================================

/// Authenticated encryption with associated data (AEAD) scheme
pub(crate) trait AeadScheme {
    const KEY_SIZE: usize;

    type Key: Deserializable + Zeroize + ZeroizeOnDrop;

    fn key_from_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError>;

    // BYTE METHODS
    // ================================================================================================

    fn encrypt_bytes<R: rand::CryptoRng + rand::RngCore>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    fn decrypt_bytes_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    // FELT METHODS
    // ================================================================================================

    /// Encrypts field elements with associated data. Default implementation converts to bytes.
    fn encrypt_elements<R: rand::CryptoRng + rand::RngCore>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<u8>, EncryptionError> {
        let plaintext_bytes = crate::utils::elements_to_bytes(plaintext);
        let ad_bytes = crate::utils::elements_to_bytes(associated_data);

        Self::encrypt_bytes(key, rng, &plaintext_bytes, &ad_bytes)
    }

    /// Decrypts field elements with associated data. Default implementation uses byte decryption.
    fn decrypt_elements_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        let ad_bytes = crate::utils::elements_to_bytes(associated_data);
        let plaintext_bytes = Self::decrypt_bytes_with_associated_data(key, ciphertext, &ad_bytes)?;

        match crate::utils::bytes_to_elements_exact(&plaintext_bytes) {
            Some(elements) => Ok(elements),
            None => Err(EncryptionError::FailedBytesToElementsConversion),
        }
    }
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
    /// Padding is malformed
    MalformedPadding,
    /// Ciphertext length, in field elements, is not a multiple of `RATE_WIDTH`
    CiphertextLenNotMultipleRate,
    /// Wrong decryption method used for the given data type
    InvalidDataType { expected: DataType, found: DataType },
    /// Failed to convert a sequence of bytes, supposed to originate from a sequence of field
    /// elements
    FailedBytesToElementsConversion,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InvalidAuthTag => write!(f, "authentication tag verification failed"),
            EncryptionError::FailedOperation => write!(f, "operation failed"),
            EncryptionError::MalformedPadding => write!(f, "malformed padding"),
            EncryptionError::CiphertextLenNotMultipleRate => {
                write!(f, "ciphertext length, in field elements, is not a multiple of `RATE_WIDTH`")
            },
            EncryptionError::InvalidDataType { expected, found } => {
                write!(f, "invalid data type: expected {expected:?}, found {found:?}")
            },
            EncryptionError::FailedBytesToElementsConversion => write!(
                f,
                "failed to convert bytes, that are supposed to originate from field elements, back to field elements"
            ),
        }
    }
}

impl core::error::Error for EncryptionError {}

/// Error type for invalid `DataType` conversions.
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidDataTypeError {
    pub value: u8,
}

impl fmt::Display for InvalidDataTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid data type value: (expected 0 for Elements or 1 for Bytes)")
    }
}

impl core::error::Error for InvalidDataTypeError {}
