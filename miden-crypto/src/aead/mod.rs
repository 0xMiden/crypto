//! AEAD (authenticated encryption with associated data) schemes.

use core::fmt;

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
