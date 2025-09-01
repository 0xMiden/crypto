//! Cryptographic utilities for encrypting and decrypting data using XChaCha20-Poly1305 AEAD.
//!
//! This module provides secure encryption and decryption functionality for both raw bytes
//! and field elements (Felt). It uses the XChaCha20-Poly1305 authenticated encryption with
//! associated data (AEAD) algorithm, which provides both confidentiality and integrity.
//!
//! # Key Components
//!
//! - [`SecretKey`]: A 256-bit secret key for encryption and decryption operations
//! - [`Nonce`]: A 192-bit nonce that should be sampled randomly per encryption operation
//! - [`EncryptedData`]: Encrypted data stored as bytes
//! - [`EncryptedFeltData`]: Encrypted data stored as field elements
//!
//! # Usage
//!
//! ```rust
//! use crate::encryption::xchacha::SecretKey;
//!
//! // Generate a new secret key
//! let key = SecretKey::new();
//!
//! // Encrypt some data
//! let data = b"Hello, world!";
//! let encrypted = key.encrypt_bytes(data)?;
//!
//! // Decrypt the data
//! let decrypted = key.decrypt_bytes(&encrypted)?;
//! assert_eq!(data, &decrypted[..]);
//! `
use alloc::vec::Vec;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{CryptoRng, RngCore};
use winter_math::FieldElement;
use zeroize::Zeroize;

#[cfg(feature = "std")]
use crate::encryption::EncryptionError;
use crate::{
    Felt,
    encryption::BINARY_CHUNK_SIZE,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

#[cfg(test)]
mod test;

// CONSTANTS
// ================================================================================================

/// Size of the nonce once it is encoded as field elements
const NONCE_SIZE_FELT: usize = 4;
/// Size of nonce in bytes
const NONCE_SIZE_BYTES: usize = 24;
/// Size of secret key in bytes
const SK_SIZE_BYTES: usize = 32;

// STRUCTS AND IMPLEMENTATIONS
// ================================================================================================

/// A 192-bit nonce
///
/// Note: This should be drawn randomly from a CSPRNG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    inner: chacha20poly1305::XNonce,
}

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // we use a seedable CSPRNG and seed it with `rng`
        // this is a work around the fact that the version of the `rand` dependency in our crate
        // is different than the one used in the `chacha20poly1305`. This solution will
        // no longer be needed once `chacha20poly1305` gets a new release with a version of
        // the `rand` dependency matching ours
        use chacha20poly1305::aead::rand_core::SeedableRng;
        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(rng, &mut seed);
        let rng = rand_hc::Hc128Rng::from_seed(seed);

        Nonce {
            inner: XChaCha20Poly1305::generate_nonce(rng),
        }
    }

    /// Creates a new nonce from the provided array of bytes
    pub fn from_slice(bytes: &[u8; NONCE_SIZE_BYTES]) -> Self {
        Nonce { inner: (*bytes).into() }
    }
}

/// A 256-bit secret key
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey([u8; SK_SIZE_BYTES]);

impl SecretKey {
    /// Creates a new random secret key using the default random number generator
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self::with_rng(&mut rng)
    }

    /// Creates a new random secret key using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // we use a seedable CSPRNG and seed it with `rng`
        // this is a work around the fact that the version of the `rand` dependency in our crate
        // is different than the one used in the `chacha20poly1305`. This solution will
        // no longer be needed once `chacha20poly1305` gets a new release with a version of
        // the `rand` dependency matching ours
        use chacha20poly1305::aead::rand_core::SeedableRng;
        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(rng, &mut seed);
        let rng = rand_hc::Hc128Rng::from_seed(seed);

        let key = XChaCha20Poly1305::generate_key(rng);
        Self(key.into())
    }

    /// Encrypts, as Felt-s, and authenticates the provided data using this secret key and a random
    /// nonce
    #[cfg(feature = "std")]
    pub fn encrypt(&self, data: &[Felt]) -> Result<EncryptedFeltData, EncryptionError> {
        self.encrypt_with_associated_data(data, &[])
    }

    /// Encrypts, as Felt-s, the provided data and authenticates both the ciphertext as well as
    /// the provided associated data using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt_with_associated_data(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
    ) -> Result<EncryptedFeltData, EncryptionError> {
        let mut rng = rand::rng();

        let nonce = Nonce::with_rng(&mut rng);
        self.encrypt_with_nonce(data, associated_data, nonce)
    }

    /// Encrypts the provided data using this secret key and a specified nonce
    pub fn encrypt_with_nonce(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
        nonce: Nonce,
    ) -> Result<EncryptedFeltData, EncryptionError> {
        let data_byte = felts_to_bytes_unchecked(data);
        let ad_byte = felts_to_bytes_unchecked(associated_data);
        let payload = chacha20poly1305::aead::Payload { msg: &data_byte, aad: &ad_byte };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        let ciphertext = cipher
            .encrypt(&nonce.inner, payload)
            .map_err(|_| (EncryptionError::FailedOperation))?;

        let ciphertext_felt = bytes_to_felts(&ciphertext);
        let nonce_felt = bytes_to_felts(nonce.inner.as_slice())
            .try_into()
            .expect("should not fail given the size of nonce");

        Ok(EncryptedFeltData {
            ciphertext: ciphertext_felt,
            nonce: nonce_felt,
        })
    }

    /// Encrypts, as bytes, and authenticates the provided data using this secret key and a random
    /// nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(&self, data: &[u8]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_bytes_with_associated_data(data, &[])
    }

    /// Encrypts, as bytes, the provided data and authenticates both the ciphertext as well as
    /// the provided associated data using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes_with_associated_data(
        &self,
        data: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedData, EncryptionError> {
        let mut rng = rand::rng();
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_bytes_with_nonce(data, associated_data, nonce)
    }

    /// Encrypts the provided data, as bytes, using this secret key and a specified nonce
    pub fn encrypt_bytes_with_nonce(
        &self,
        data: &[u8],
        associated_data: &[u8],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        let payload = chacha20poly1305::aead::Payload { msg: data, aad: associated_data };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        let ciphertext = cipher
            .encrypt(&nonce.inner, payload)
            .map_err(|_| (EncryptionError::FailedOperation))?;

        Ok(EncryptedData { ciphertext, nonce })
    }

    /// Decrypts the provided encrypted data, as field elements, using this secret key
    pub fn decrypt(
        &self,
        encrypted_data: &EncryptedFeltData,
    ) -> Result<Vec<Felt>, EncryptionError> {
        self.decrypt_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts the provided encrypted data, as field elements, given some associated data using
    /// this secret key
    pub fn decrypt_with_associated_data(
        &self,
        encrypted_data: &EncryptedFeltData,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        let EncryptedFeltData { ciphertext, nonce } = encrypted_data;
        let ciphertext = &felts_to_bytes(ciphertext)?;

        let nonce_bytes: [u8; NONCE_SIZE_BYTES] = felts_to_bytes(nonce)?
            .try_into()
            .expect("should not fail given the size of nonce");
        let nonce = Nonce::from_slice(&nonce_bytes);

        let associated_data = &felts_to_bytes_unchecked(associated_data);
        let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        let plaintext = cipher
            .decrypt(&nonce.inner, payload)
            .map_err(|_| EncryptionError::FailedOperation)?;
        let plaintext_felt = bytes_to_felts_unchecked(&plaintext);

        Ok(plaintext_felt)
    }

    /// Decrypts the provided encrypted data, as bytes, using this secret key
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_bytes_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts the provided encrypted data, as bytes, given some associated data using
    /// this secret key
    pub fn decrypt_bytes_with_associated_data(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let EncryptedData { ciphertext, nonce } = encrypted_data;
        let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        cipher
            .decrypt(&nonce.inner, payload)
            .map_err(|_| EncryptionError::FailedOperation)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypted data as bytes
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// The encrypted ciphertext
    ciphertext: Vec<u8>,
    /// The nonce used during encryption
    nonce: Nonce,
}

/// Encrypted data as field elements
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedFeltData {
    /// The encrypted ciphertext
    ciphertext: Vec<Felt>,
    /// The nonce used during encryption
    nonce: [Felt; NONCE_SIZE_FELT],
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let inner: [u8; SK_SIZE_BYTES] = source.read_array()?;

        Ok(SecretKey(inner))
    }
}

impl Serializable for Nonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.inner.as_slice());
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let inner: [u8; NONCE_SIZE_BYTES] = source.read_array()?;

        Ok(Nonce {
            inner: chacha20poly1305::XNonce::clone_from_slice(&inner),
        })
    }
}

impl Serializable for EncryptedData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.ciphertext.len());
        target.write_bytes(&self.ciphertext);

        target.write_bytes(&self.nonce.inner);
    }
}

impl Deserializable for EncryptedData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let ciphertext_len = source.read_usize()?;
        let ciphertext = source.read_vec(ciphertext_len)?;

        let inner: [u8; NONCE_SIZE_BYTES] = source.read_array()?;

        Ok(Self {
            ciphertext,
            nonce: Nonce { inner: inner.into() },
        })
    }
}

impl Serializable for EncryptedFeltData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let ciphertext = &felts_to_bytes(&self.ciphertext)
            .expect("should not fail as it is the result of bytes_to_felts");

        target.write_usize(ciphertext.len());
        target.write_bytes(ciphertext);

        target.write_bytes(
            &felts_to_bytes(&self.nonce)
                .expect("should not fail as it is the result of bytes_to_felts"),
        );
    }
}

impl Deserializable for EncryptedFeltData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let ciphertext_len = source.read_usize()?;
        let ciphertext_bytes = source.read_vec(ciphertext_len)?;
        let ciphertext = bytes_to_felts(&ciphertext_bytes);

        let nonce_bytes: [u8; NONCE_SIZE_BYTES] = source.read_array()?;
        let nonce = bytes_to_felts(&nonce_bytes)
            .try_into()
            .expect("should not fail given the size of the nonce");

        Ok(Self { ciphertext, nonce })
    }
}

//  HELPERS
// ================================================================================================

/// Converts bytes to field elements without validation.
///
/// Assumes the input bytes originated from a vector of `Felt` elements and uses
/// the full `ELEMENT_BYTES` capacity per field element. This function will panic
/// if the assumption doesn't hold (e.g., if chunk size doesn't match `ELEMENT_BYTES`).
///
/// # Arguments
/// * `bytes` - Byte slice that must be a multiple of `Felt::ELEMENT_BYTES` in length
///
/// # Returns
/// Vector of `Felt` elements reconstructed from the byte chunks
///
/// # Panics
/// Panics if any chunk cannot be converted to `ELEMENT_BYTES` array
fn bytes_to_felts_unchecked(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(Felt::ELEMENT_BYTES)
        .map(|chunk| {
            Felt::new(u64::from_le_bytes(
                chunk.try_into().expect("should not fail by construction"),
            ))
        })
        .collect()
}

/// Converts field elements back to their raw byte representation.
///
/// Each `Felt` is converted to its full `ELEMENT_BYTES` representation without
/// any padding removal or validation. This is the inverse of `bytes_to_felts_unchecked`.
///
/// # Arguments
/// * `felts` - Slice of field elements to convert
///
/// # Returns
/// Vector containing the raw bytes from all field elements
fn felts_to_bytes_unchecked(felts: &[Felt]) -> Vec<u8> {
    let number_felts = felts.len();
    let mut result = Vec::with_capacity(number_felts * Felt::ELEMENT_BYTES);
    for felt in felts.iter().take(number_felts) {
        let felt_bytes = felt.as_int().to_le_bytes();
        result.extend_from_slice(&felt_bytes);
    }

    result
}

/// Converts bytes to field elements with padding.
///
/// Packs bytes into chunks of `BINARY_CHUNK_SIZE` and adds padding to the final chunk using a `1`
/// bit followed by zeros. This ensures the original bytes can be recovered during decoding
/// without any ambiguity.
///
/// # Arguments
/// * `bytes` - Byte slice to encode
///
/// # Returns
/// Vector of `Felt` elements with the last element containing padding
fn bytes_to_felts(bytes: &[u8]) -> Vec<Felt> {
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

/// Converts padded field elements back to the original bytes.
///
/// Reconstructs the original byte sequence by removing the padding added by
/// `bytes_to_felts`. The padding consists of a `1` bit followed by zeros in
/// the final field element.
///
/// # Arguments
/// * `felts` - Slice of field elements with padding in the last element
///
/// # Returns
/// * `Ok(Vec<u8>)` - The original byte sequence with padding removed
/// * `Err(EncryptionError::MalformedPadding)` - If no padding marker (`1` bit) is found
fn felts_to_bytes(felts: &[Felt]) -> Result<Vec<u8>, EncryptionError> {
    let number_felts = felts.len();
    if number_felts == 0 {
        return Ok(vec![]);
    }

    let mut result = Vec::with_capacity(number_felts * BINARY_CHUNK_SIZE);
    for felt in felts.iter().take(number_felts - 1) {
        let felt_bytes = felt.as_int().to_le_bytes();
        result.extend_from_slice(&felt_bytes[..BINARY_CHUNK_SIZE]);
    }

    // handle the last field element
    let felt_bytes = felts[number_felts - 1].as_int().to_le_bytes();
    let pos = match felt_bytes.iter().rposition(|entry| *entry == 1_u8) {
        Some(pos) => pos,
        None => return Err(EncryptionError::MalformedPadding),
    };

    result.extend_from_slice(&felt_bytes[..pos]);
    Ok(result)
}
