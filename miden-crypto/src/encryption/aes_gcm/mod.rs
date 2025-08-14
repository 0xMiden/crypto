use alloc::vec::Vec;

use aes_gcm::{
    Aes256Gcm, Error,
    aead::{
        Aead, AeadCore, KeyInit,
        rand_core::{CryptoRng, RngCore},
    },
};
use sha3::digest::consts::U12;
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{
    Felt,
    encryption::{BINARY_CHUNK_SIZE, rpo::EncryptionError},
};

#[cfg(test)]
mod test;

/// The nonce which is of size 96-bit
#[derive(Debug, PartialEq, Eq)]
pub struct Nonce {
    inner: aes_gcm::Nonce<U12>,
}

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Nonce { inner: Aes256Gcm::generate_nonce(rng) }
    }

    /// Creates a new nonce from the provided array of bytes
    pub fn from_slice(bytes: &[u8; 12]) -> Self {
        Nonce { inner: (*bytes).into() }
    }
}

/// A 256-bit secret key
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Creates a new random secret key using the default random number generator
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        use aes_gcm::aead::rand_core::OsRng;
        Self::with_rng(&mut OsRng)
    }

    /// Creates a new random secret key using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = Aes256Gcm::generate_key(rng);
        Self(key.into())
    }

    /// Encrypts the provided data, as Felt-s, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
    ) -> Result<EncryptedData, EncryptionError> {
        use aes_gcm::aead::rand_core::OsRng;

        let mut rng = OsRng;
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_with_nonce(data, associated_data, nonce)
    }

    /// Encrypts the provided data using this secret key and a specified nonce
    pub fn encrypt_with_nonce(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        let data_byte = felts_to_bytes(data);
        let ad_byte = felts_to_bytes(associated_data);
        let payload = aes_gcm::aead::Payload { msg: &data_byte, aad: &ad_byte };

        let cipher = Aes256Gcm::new(&self.0.into());

        let ciphertext = cipher
            .encrypt(&nonce.inner, payload)
            .map_err(|_| (EncryptionError::FailedOperation))?;

        Ok(EncryptedData {
            associated_data: ad_byte,
            ciphertext,
            nonce,
        })
    }

    /// Encrypts the provided data, as bytes, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(
        &self,
        data: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedData, EncryptionError> {
        let mut rng = aes_gcm::aead::OsRng;
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
        let payload = aes_gcm::aead::Payload { msg: data, aad: associated_data };

        let cipher = Aes256Gcm::new(&self.0.into());

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
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<Felt>, EncryptionError> {
        let EncryptedData { associated_data, ciphertext, nonce } = encrypted_data;
        let payload = aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = Aes256Gcm::new(&self.0.into());

        let plaintext = cipher.decrypt(&nonce.inner, payload)?;
        let plaintext_felt = bytes_to_felts(&plaintext);

        Ok(plaintext_felt)
    }

    /// Decrypts the provided encrypted data, as bytes, using this secret key
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        let EncryptedData { associated_data, ciphertext, nonce } = encrypted_data;
        let payload = aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = Aes256Gcm::new(&self.0.into());

        Ok(cipher.decrypt(&nonce.inner, payload)?)
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

        let inner: [u8; 12] = source.read_array()?;

        Ok(Self {
            associated_data,
            ciphertext,
            nonce: Nonce { inner: inner.into() },
        })
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

//  ERRORS
// ================================================================================================

impl From<Error> for EncryptionError {
    fn from(_err: Error) -> Self {
        EncryptionError::FailedOperation
    }
}
