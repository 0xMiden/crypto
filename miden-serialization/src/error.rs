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

/// Helper trait to convert errors to DeserializationError
pub trait IntoDeserError {
    fn into_deser_error(self) -> DeserializationError;
}

impl IntoDeserError for DeserializationError {
    fn into_deser_error(self) -> DeserializationError {
        self
    }
}

// Allow converting from embedded_io ErrorKind
impl IntoDeserError for embedded_io::ErrorKind {
    #[cfg(feature = "alloc")]
    fn into_deser_error(self) -> DeserializationError {
        match self {
            embedded_io::ErrorKind::InvalidData => {
                DeserializationError::InvalidValue("invalid data".into())
            }
            _ => DeserializationError::UnknownError("io error".into()),
        }
    }

    #[cfg(not(feature = "alloc"))]
    fn into_deser_error(self) -> DeserializationError {
        match self {
            embedded_io::ErrorKind::InvalidData => {
                DeserializationError::InvalidValue("invalid data")
            }
            _ => DeserializationError::UnknownError("io error"),
        }
    }
}
