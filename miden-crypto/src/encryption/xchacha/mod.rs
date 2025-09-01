use alloc::vec::Vec;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{CryptoRng, RngCore};
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

/// A 192-bit nonce
///
/// Note: This should be drawn randomly from a CSPRNG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    inner: chacha20poly1305::XNonce,
}

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let rng = chacha20poly1305::aead::rand_core::OsRng;
        Nonce {
            inner: XChaCha20Poly1305::generate_nonce(rng),
        }
    }

    /// Creates a new nonce from the provided array of bytes
    pub fn from_slice(bytes: &[u8; 24]) -> Self {
        Nonce { inner: (*bytes).into() }
    }
}

/// A 256-bit secret key
#[derive(Debug, PartialEq, Eq, Zeroize)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Creates a new random secret key using the default random number generator
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self::with_rng(&mut rng)
    }

    /// Creates a new random secret key using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let rng = chacha20poly1305::aead::rand_core::OsRng;

        let key = XChaCha20Poly1305::generate_key(rng);
        Self(key.into())
    }

    /// Encrypts the provided data, as Felt-s, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
    ) -> Result<EncryptedDataFelt, EncryptionError> {
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
    ) -> Result<EncryptedDataFelt, EncryptionError> {
        let data_byte = felts_to_bytes(data);
        let ad_byte = felts_to_bytes(associated_data);
        let payload = chacha20poly1305::aead::Payload { msg: &data_byte, aad: &ad_byte };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        let ciphertext = cipher
            .encrypt(&nonce.inner, payload)
            .map_err(|_| (EncryptionError::FailedOperation))?;

        let ciphertext_felt = bytes_to_felts(&ciphertext);
        let nonce_felt = bytes_to_felts(nonce.inner.as_slice()).try_into().unwrap();

        Ok(EncryptedDataFelt {
            associated_data: associated_data.to_vec(),
            ciphertext: ciphertext_felt,
            nonce: nonce_felt,
        })
    }

    /// Encrypts the provided data, as bytes, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(
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

        Ok(EncryptedData {
            associated_data: associated_data.into(),
            ciphertext,
            nonce,
        })
    }

    /// Decrypts the provided encrypted data using this secret key
    pub fn decrypt(
        &self,
        encrypted_data: &EncryptedDataFelt,
    ) -> Result<Vec<Felt>, EncryptionError> {
        let EncryptedDataFelt { associated_data, ciphertext, nonce } = encrypted_data;
        let associated_data = &felts_to_bytes(associated_data);
        let ciphertext = &felts_to_bytes(ciphertext);
        let nonce_bytes: [u8; 24] = felts_to_bytes(nonce).try_into().unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = XChaCha20Poly1305::new(&self.0.into());

        let plaintext = cipher
            .decrypt(&nonce.inner, payload)
            .map_err(|_| EncryptionError::FailedOperation)?;
        let plaintext_felt = bytes_to_felts(&plaintext);

        Ok(plaintext_felt)
    }

    /// Decrypts the provided encrypted data, as bytes, using this secret key
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        let EncryptedData { associated_data, ciphertext, nonce } = encrypted_data;
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

/// Encrypted data
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// The associated data
    associated_data: Vec<u8>,
    /// The encrypted ciphertext
    ciphertext: Vec<u8>,
    /// The nonce used during encryption
    nonce: Nonce,
}

impl EncryptedData {
    /// Returns the associated data to the encrypted data.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
}

/// Encrypted data
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedDataFelt {
    /// The associated data
    associated_data: Vec<Felt>,
    /// The encrypted ciphertext
    ciphertext: Vec<Felt>,
    /// The nonce used during encryption
    nonce: [Felt; 3],
}

impl EncryptedDataFelt {
    /// Returns the associated data to the encrypted data.
    pub fn associated_data(&self) -> &[Felt] {
        &self.associated_data
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
        let inner: [u8; 32] = source.read_array()?;

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
        let inner: [u8; 32] = source.read_array()?;

        Ok(Nonce {
            inner: chacha20poly1305::XNonce::clone_from_slice(&inner),
        })
    }
}

impl Serializable for EncryptedData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let associated_data_len = self.associated_data.len() as u32;
        let ciphertext_len = self.ciphertext.len() as u64;

        target.write_u32(associated_data_len);
        target.write_bytes(&self.associated_data);
        target.write_u64(ciphertext_len);
        target.write_bytes(&self.ciphertext);

        target.write_bytes(&self.nonce.inner);
    }
}

impl Deserializable for EncryptedData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let associated_data_len = source.read_u32()?;
        let associated_data = source.read_vec(associated_data_len as usize)?;

        let ciphertext_len = source.read_u64()?;
        let ciphertext = source.read_vec(ciphertext_len as usize)?;

        let inner: [u8; 24] = source.read_array()?;

        Ok(Self {
            associated_data,
            ciphertext,
            nonce: Nonce { inner: inner.into() },
        })
    }
}

impl Serializable for EncryptedDataFelt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let associated_data_len = self.associated_data.len() as u32;
        let ciphertext_len = self.ciphertext.len() as u64;

        target.write_u32(associated_data_len);
        target.write_bytes(&felts_to_bytes(&self.associated_data));
        target.write_u64(ciphertext_len);
        target.write_bytes(&felts_to_bytes(&self.ciphertext));

        target.write_bytes(&felts_to_bytes(&self.nonce));
    }
}

impl Deserializable for EncryptedDataFelt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let associated_data_len = source.read_u32()?;
        let associated_data_bytes = source.read_vec(8 * associated_data_len as usize)?;
        let associated_data = bytes_to_felts(&associated_data_bytes);

        let ciphertext_len = source.read_u64()?;
        let ciphertext_bytes = source.read_vec(8 * ciphertext_len as usize)?;
        let ciphertext = bytes_to_felts(&ciphertext_bytes);

        let nonce_bytes: [u8; 24] = source.read_array()?;
        let nonce = bytes_to_felts(&nonce_bytes).try_into().unwrap();

        Ok(Self { associated_data, ciphertext, nonce })
    }
}

//  HELPERS
// ================================================================================================

/// Converts bytes to field elements
///
/// It assumes that the bytes originated from a vector of `Felt` and panics if this assumption does
/// not hold.
fn bytes_to_felts(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            Felt::new(u64::from_le_bytes(
                chunk.try_into().expect("should not fail by construction"),
            ))
        })
        .collect()
}

/// Converts field elements back to bytes
fn felts_to_bytes(felts: &[Felt]) -> Vec<u8> {
    let number_felts = felts.len();
    let mut result = Vec::with_capacity(number_felts * BINARY_CHUNK_SIZE);
    for felt in felts.iter().take(number_felts) {
        let felt_bytes = felt.as_int().to_le_bytes();
        result.extend_from_slice(&felt_bytes);
    }

    result
}
