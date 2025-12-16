//! Error types for deserialization operations.

use core::fmt;

/// Errors that can occur during deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeserializationError {
    /// Unexpected end of file/data
    UnexpectedEOF,
    /// Invalid value encountered during deserialization
    InvalidValue(
        #[cfg(feature = "alloc")]
        alloc::string::String,
        #[cfg(not(feature = "alloc"))]
        &'static str,
    ),
    /// Unknown error with description
    UnknownError(
        #[cfg(feature = "alloc")]
        alloc::string::String,
        #[cfg(not(feature = "alloc"))]
        &'static str,
    ),
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEOF => write!(f, "unexpected end of data"),
            Self::InvalidValue(msg) => write!(f, "invalid value: {}", msg),
            Self::UnknownError(msg) => write!(f, "unknown error: {}", msg),
        }
    }
}

// Implement core::error::Error for DeserializationError (required by embedded_io::Error)
impl core::error::Error for DeserializationError {}

// Implement embedded_io::Error for DeserializationError
impl embedded_io::Error for DeserializationError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::UnexpectedEOF => embedded_io::ErrorKind::Other,
            Self::InvalidValue(_) => embedded_io::ErrorKind::InvalidData,
            Self::UnknownError(_) => embedded_io::ErrorKind::Other,
        }
    }
}

// Note: IntoDeserError trait was removed as it was not being used.
// Error conversion is handled through the embedded_io::Error trait implementation.
