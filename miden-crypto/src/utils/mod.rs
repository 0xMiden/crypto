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

use crate::{Felt, FieldElement, StarkField, Word};

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
    #[error("hex encoded data must contain only characters [0-9a-fA-F]")]
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

// CONVERSIONS BETWEEN BYTES AND ELEMENTS
// ================================================================================================

/// Converts a sequence of bytes into vector field elements with padding. This guarantees that no
/// two sequences or bytes map to the same sequence of field elements.
///
/// Packs bytes into chunks of `BINARY_CHUNK_SIZE` and adds padding to the final chunk using a `1`
/// bit followed by zeros. This ensures the original bytes can be recovered during decoding without
/// any ambiguity.
///
/// Note that by the endianness of the conversion as well as the fact that we are packing at most
/// `56 = 7 * 8` bits in each field element, the padding above with `1` should never overflow the
/// field size.
///
/// # Arguments
/// * `bytes` - Byte slice to encode
///
/// # Returns
/// Vector of `Felt` elements with the last element containing padding
pub fn bytes_to_elements_with_padding(bytes: &[u8]) -> Vec<Felt> {
    if bytes.is_empty() {
        return vec![];
    }

    // determine the number of field elements needed to encode `bytes` when each field element
    // represents at most 7 bytes.
    let num_field_elem = bytes.len().div_ceil(BINARY_CHUNK_SIZE);

    // initialize a buffer to receive the little-endian elements.
    let mut buf = [0_u8; 8];

    // iterate the chunks of bytes, creating a field element from each chunk
    let last_chunk_idx = num_field_elem - 1;

    bytes
        .chunks(BINARY_CHUNK_SIZE)
        .enumerate()
        .map(|(current_chunk_idx, chunk)| {
            // copy the chunk into the buffer
            if current_chunk_idx != last_chunk_idx {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                // on the last iteration, we pad `buf` with a 1 followed by as many 0's as are
                // needed to fill it
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }

            Felt::new(u64::from_le_bytes(buf))
        })
        .collect()
}

/// Converts a sequence of padded field elements back to the original bytes.
///
/// Reconstructs the original byte sequence by removing the padding added by `bytes_to_felts`.
/// The padding consists of a `1` bit followed by zeros in the final field element.
///
/// Note that by the endianness of the conversion as well as the fact that we are packing at most
/// `56 = 7 * 8` bits in each field element, the padding above with `1` should never overflow the
/// field size.
///
/// # Arguments
/// * `felts` - Slice of field elements with padding in the last element
///
/// # Returns
/// * `Some(Vec<u8>)` - The original byte sequence with padding removed
/// * `None` - If no padding marker (`1` bit) is found
pub fn padded_elements_to_bytes(felts: &[Felt]) -> Option<Vec<u8>> {
    let number_felts = felts.len();
    if number_felts == 0 {
        return Some(vec![]);
    }

    let mut result = Vec::with_capacity(number_felts * BINARY_CHUNK_SIZE);
    for felt in felts.iter().take(number_felts - 1) {
        let felt_bytes = felt.as_int().to_le_bytes();
        result.extend_from_slice(&felt_bytes[..BINARY_CHUNK_SIZE]);
    }

    // handle the last field element
    let felt_bytes = felts[number_felts - 1].as_int().to_le_bytes();
    let pos = felt_bytes.iter().rposition(|entry| *entry == 1_u8)?;

    result.extend_from_slice(&felt_bytes[..pos]);
    Some(result)
}

/// Converts field elements to raw byte representation.
///
/// Each `Felt` is converted to its full `ELEMENT_BYTES` representation, in little-endian form
/// and canonical form, without any padding removal or validation. This is the inverse
/// of `bytes_to_elements_exact`.
///
/// # Arguments
/// * `felts` - Slice of field elements to convert
///
/// # Returns
/// Vector containing the raw bytes from all field elements
pub fn elements_to_bytes(felts: &[Felt]) -> Vec<u8> {
    let number_felts = felts.len();
    let mut result = Vec::with_capacity(number_felts * Felt::ELEMENT_BYTES);
    for felt in felts.iter().take(number_felts) {
        let felt_bytes = felt.as_int().to_le_bytes();
        result.extend_from_slice(&felt_bytes);
    }

    result
}

/// Converts bytes to field elements with validation.
///
/// This function validates that:
/// - The input bytes length is divisible by `Felt::ELEMENT_BYTES`
/// - All `Felt::ELEMENT_BYTES`-byte sequences represent valid field elements
///
/// # Arguments
/// * `bytes` - Byte slice that must be a multiple of `Felt::ELEMENT_BYTES` in length
///
/// # Returns
/// `Option<Vec<Felt>>` - Vector of `Felt` elements if all validations pass, or None otherwise
pub fn bytes_to_elements_exact(bytes: &[u8]) -> Option<Vec<Felt>> {
    // Check that the length is divisible by ELEMENT_BYTES
    if !bytes.len().is_multiple_of(Felt::ELEMENT_BYTES) {
        return None;
    }

    let mut result = Vec::with_capacity(bytes.len() / Felt::ELEMENT_BYTES);

    for chunk in bytes.chunks_exact(Felt::ELEMENT_BYTES) {
        let chunk_array: [u8; Felt::ELEMENT_BYTES] =
            chunk.try_into().expect("should succeed given the length check above");

        let value = u64::from_le_bytes(chunk_array);

        // Validate that the value represents a valid field element
        if value >= Felt::MODULUS {
            return None;
        }

        result.push(Felt::new(value));
    }

    Some(result)
}

/// Converts bytes to field elements using u32 packing in little-endian format.
///
/// Each field element contains a u32 value representing up to 4 bytes. If the byte length
/// is not a multiple of 4, the final field element is zero-padded.
///
/// # Arguments
/// - `bytes`: The byte slice to convert
///
/// # Returns
/// A vector of field elements, each containing 4 bytes packed in little-endian order.
///
/// # Examples
/// ```rust
/// # use miden_crypto::{Felt, utils::bytes_to_packed_u32_elements};
///
/// let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
/// let felts = bytes_to_packed_u32_elements(&bytes);
/// assert_eq!(felts, vec![Felt::new(0x04030201), Felt::new(0x00000005)]);
/// ```
pub fn bytes_to_packed_u32_elements(bytes: &[u8]) -> Vec<Felt> {
    const BYTES_PER_U32: usize = core::mem::size_of::<u32>();

    bytes
        .chunks(BYTES_PER_U32)
        .map(|chunk| {
            // Pack up to 4 bytes into a u32 in little-endian format
            let mut packed = [0u8; BYTES_PER_U32];
            packed[..chunk.len()].copy_from_slice(chunk);
            Felt::from(u32::from_le_bytes(packed))
        })
        .collect()
}
