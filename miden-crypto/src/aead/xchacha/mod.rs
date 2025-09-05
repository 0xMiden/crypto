//! Cryptographic utilities for encrypting and decrypting data using XChaCha20-Poly1305 AEAD.
//!
//! This module provides secure encryption and decryption functionality. It uses
//! the XChaCha20-Poly1305 authenticated encryption with associated data (AEAD) algorithm,
//! which provides both confidentiality and integrity.
//!
//! # Key Components
//!
//! - [`SecretKey`]: A 256-bit secret key for encryption and decryption operations
//! - [`Nonce`]: A 192-bit nonce that should be sampled randomly per encryption operation
//! - [`EncryptedData`]: Encrypted data
use alloc::vec::Vec;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    aead::EncryptionError,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

#[cfg(test)]
mod test;

// CONSTANTS
// ================================================================================================

/// Size of nonce in bytes
const NONCE_SIZE_BYTES: usize = 24;
/// Size of secret key in bytes
const SK_SIZE_BYTES: usize = 32;

// STRUCTS AND IMPLEMENTATIONS
// ================================================================================================

/// Encrypted data
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// The encrypted ciphertext, including the authentication tag
    ciphertext: Vec<u8>,
    /// The nonce used during encryption
    nonce: Nonce,
}

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
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

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

    // BYTE ENCRYPTION
    // --------------------------------------------------------------------------------------------

    /// Encrypts and authenticates the provided data using this secret key and a random
    /// nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(&self, data: &[u8]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_bytes_with_associated_data(data, &[])
    }

    /// Encrypts the provided data and authenticates both the ciphertext as well as
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

    /// Encrypts the provided data using this secret key and a specified nonce
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
            .map_err(|_| EncryptionError::FailedOperation)?;

        Ok(EncryptedData { ciphertext, nonce })
    }

    // DECRYPTION
    // --------------------------------------------------------------------------------------------

    /// Decrypts the provided encrypted data using this secret key
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_bytes_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts the provided encrypted data given some associated data using
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
