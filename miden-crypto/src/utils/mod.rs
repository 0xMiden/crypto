//! Utilities used in this crate which can also be generally useful downstream.

use alloc::{string::String, vec::Vec};
use core::fmt::{self, Write};

use thiserror::Error;
#[cfg(feature = "std")]
pub use winter_utils::ReadAdapter;
pub use winter_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    uninit_vector,
};

use crate::{Felt, StarkField, Word};

// CONSTANTS
// ================================================================================================

/// The number of byte chunks that can be safely embedded in a field element
const BINARY_CHUNK_SIZE: usize = 7;

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts a [Word] into hex.
pub fn word_to_hex(w: &Word) -> Result<String, fmt::Error> {
    let mut s = String::new();

    for byte in w.iter().flat_map(|e| e.to_bytes()) {
        write!(s, "{byte:02x}")?;
    }

    Ok(s)
}

/// Renders an array of bytes as hex into a String.
pub fn bytes_to_hex_string<const N: usize>(data: [u8; N]) -> String {
    let mut s = String::with_capacity(N + 2);

    s.push_str("0x");
    for byte in data.iter() {
        write!(s, "{byte:02x}").expect("formatting hex failed");
    }

    s
}

/// Defines errors which can occur during parsing of hexadecimal strings.
#[derive(Debug, Error)]
pub enum HexParseError {
    #[error("expected hex data to have length {expected}, including the 0x prefix, found {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("hex encoded data must start with 0x prefix")]
    MissingPrefix,
    #[error("hex encoded data must contain only characters [a-zA-Z0-9]")]
    InvalidChar,
    #[error("hex encoded values of a Digest must be inside the field modulus")]
    OutOfRange,
}

/// Parses a hex string into an array of bytes of known size.
pub fn hex_to_bytes<const N: usize>(value: &str) -> Result<[u8; N], HexParseError> {
    let expected: usize = (N * 2) + 2;
    if value.len() != expected {
        return Err(HexParseError::InvalidLength { expected, actual: value.len() });
    }

    if !value.starts_with("0x") {
        return Err(HexParseError::MissingPrefix);
    }

    let mut data = value.bytes().skip(2).map(|v| match v {
        b'0'..=b'9' => Ok(v - b'0'),
        b'a'..=b'f' => Ok(v - b'a' + 10),
        b'A'..=b'F' => Ok(v - b'A' + 10),
        _ => Err(HexParseError::InvalidChar),
    });

    let mut decoded = [0u8; N];
    for byte in decoded.iter_mut() {
        // These `unwrap` calls are okay because the length was checked above
        let high: u8 = data.next().unwrap()?;
        let low: u8 = data.next().unwrap()?;
        *byte = (high << 4) + low;
    }

    Ok(decoded)
}

/// Converts a byte slice into a vector of field elements.
///
/// Packs bytes into chunks of 7 bytes each (the maximum that fits in a `Felt`
/// without overflow) and converts each chunk to a `Felt` using 0 padding.
///
/// # Arguments
/// * `bytes` - The byte slice to convert
///
/// # Returns
/// A vector of `Felt` elements, where each contains up to 7 bytes from the input
///
/// # Example
/// ```
/// use miden_crypto::utils::bytes_to_elements;
///
/// let data = b"Hello";
/// let elements = bytes_to_elements(data);
/// ```
pub fn bytes_to_elements(bytes: &[u8]) -> Vec<Felt> {
    // we can pack at most 7 bytes into a `Felt` without overflowing
    bytes.chunks(BINARY_CHUNK_SIZE).map(Felt::from_bytes_with_padding).collect()
}
