use alloc::vec::Vec;

use aes_gcm::{
    Aes256Gcm, Error,
    aead::{
        Aead, AeadCore, KeyInit,
        rand_core::{CryptoRng, RngCore},
    },
};
use sha3::digest::consts::U12;

use crate::{
    Felt,
    encryption::{BINARY_CHUNK_SIZE, rpo::EncryptionError},
};

#[cfg(test)]
mod test;

/// A 96-bit nonce
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    inner: aes_gcm::Nonce<U12>,
}

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Nonce { inner: Aes256Gcm::generate_nonce(rng) }
    }
}

/// A 256-bit secret key represented
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
    pub fn encrypt(&self, data: &[Felt], associated_data: &[Felt]) -> EncryptedData {
        use aes_gcm::aead::rand_core::OsRng;

        let mut rng = OsRng;
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_with_nonce(data, associated_data, &nonce)
    }

    /// Encrypts the provided data using this secret key and a specified nonce
    pub fn encrypt_with_nonce(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
        nonce: &Nonce,
    ) -> EncryptedData {
        let data_byte = felts_to_bytes(data);
        let ad_byte = felts_to_bytes(associated_data);

        let payload = aes_gcm::aead::Payload { msg: &data_byte, aad: &ad_byte };

        let cipher = Aes256Gcm::new(&self.0.into());

        let ciphertext = cipher.encrypt(&nonce.inner, payload).expect("encryption failure!");

        EncryptedData { associated_data: ad_byte, ciphertext }
    }

    /// Encrypts the provided data, as bytes, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(&self, data: &[u8], associated_data: &[u8]) -> EncryptedData {
        let mut rng = aes_gcm::aead::OsRng;
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_bytes_with_nonce(data, associated_data, &nonce)
    }

    /// Encrypts the provided data, as bytes, using this secret key and a specified nonce
    pub fn encrypt_bytes_with_nonce(
        &self,
        data: &[u8],
        associated_data: &[u8],
        nonce: &Nonce,
    ) -> EncryptedData {
        let payload = aes_gcm::aead::Payload { msg: data, aad: associated_data };

        let cipher = Aes256Gcm::new(&self.0.into());

        let ciphertext = cipher.encrypt(&nonce.inner, payload).expect("encryption failure!");

        EncryptedData {
            associated_data: associated_data.into(),
            ciphertext,
        }
    }

    /// Decrypts the provided encrypted data using this secret key
    pub fn decrypt(
        &self,
        encrypted_data: &EncryptedData,
        nonce: &Nonce,
    ) -> Result<Vec<Felt>, EncryptionError> {
        let EncryptedData { associated_data, ciphertext } = encrypted_data;

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
        nonce: &Nonce,
    ) -> Result<Vec<u8>, EncryptionError> {
        let EncryptedData { associated_data, ciphertext } = encrypted_data;

        let payload = aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data };

        let cipher = Aes256Gcm::new(&self.0.into());

        Ok(cipher.decrypt(&nonce.inner, payload)?)
    }
}

/// Encrypted data
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// The associated data
    pub associated_data: Vec<u8>,
    /// The encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

//  HELPERS
// ================================================================================================

/// Converts bytes to field elements
fn bytes_to_felts(bytes: &[u8]) -> Vec<Felt> {
    if bytes.is_empty() {
        return vec![];
    }

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
    if number_felts == 0 {
        return vec![];
    }

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
