use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, RngCore};
use winter_utils::{ByteReader, ByteWriter, DeserializationError, Serializable};
use zeroize::Zeroize;

use crate::{
    ecdh::{self, K256, KeyAgreementScheme},
    encryption::{AeadScheme, xchacha::XChaCha},
    utils::Deserializable,
};

// CRYPTO-BOX PRIMITIVE
// ================================================================================================

pub struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

#[derive(Debug)]
pub struct RawSealedMessage {
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl<K: KeyAgreementScheme, A: AeadScheme> CryptoBox<K, A> {
    pub fn seal<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RawSealedMessage, IntegratedEncryptionSchemeError> {
        let (mut ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let mut shared_secret =
            K::exchange_ephemeral_static(&ephemeral_private, recipient_public_key)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?;

        let encryption_key_bytes =
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE);
        let mut encryption_key = A::key_from_bytes(&encryption_key_bytes);

        let nonce = A::generate_nonce(rng);
        let ciphertext = A::encrypt_bytes(&encryption_key, &nonce, plaintext, associated_data)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionFailed)?;

        ephemeral_private.zeroize();
        shared_secret.zeroize();
        encryption_key.zeroize();

        Ok(RawSealedMessage {
            ciphertext,
            nonce: nonce.to_bytes(),
            ephemeral_public_key: ephemeral_public.to_bytes(),
        })
    }

    pub fn unseal(
        recipient_private_key: &K::SecretKey,
        sealed_message: &RawSealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        let ephemeral_public = K::EphemeralPublicKey::read_from_bytes(
            &sealed_message.ephemeral_public_key,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed)?;

        let mut shared_secret =
            K::exchange_static_ephemeral(recipient_private_key, &ephemeral_public)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?;

        let decryption_key_bytes =
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE);
        let mut decryption_key = A::key_from_bytes(&decryption_key_bytes);

        let nonce = A::Nonce::read_from_bytes(&sealed_message.nonce)
            .map_err(|_| IntegratedEncryptionSchemeError::InvalidNonce)?;
        let result =
            A::decrypt_bytes(&decryption_key, &nonce, &sealed_message.ciphertext, associated_data)
                .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?;

        shared_secret.zeroize();
        decryption_key.zeroize();

        Ok(result)
    }
}

// INSTANTIATIONS OF CRYPTO-BOX
// ================================================================================================

pub type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoAlgorithm {
    K256XChaCha20Poly1305 = 0,
}

impl CryptoAlgorithm {
    fn from_u8(value: u8) -> Result<Self, IntegratedEncryptionSchemeError> {
        match value {
            0 => Ok(CryptoAlgorithm::K256XChaCha20Poly1305),
            _ => Err(IntegratedEncryptionSchemeError::UnsupportedAlgorithm),
        }
    }

    fn name(self) -> &'static str {
        match self {
            CryptoAlgorithm::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
        }
    }
}

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Ephemeral public key (determines algorithm and provides key material)
    pub ephemeral_key: EphemeralPublicKey,
    /// Encrypted ciphertext with authentication tag
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
}

impl SealedMessage {
    /// Get the algorithm used to create this sealed message
    pub fn algorithm(&self) -> CryptoAlgorithm {
        self.ephemeral_key.algorithm()
    }

    /// Get the algorithm name used to create this sealed message
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }
}

/// Public key for sealing messages to a recipient
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
}

impl SealingKey {
    /// Seal (encrypt and authenticate) data for this recipient
    pub fn seal<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
        match self {
            SealingKey::K256XChaCha20Poly1305(key) => {
                let raw =
                    K256XChaCha20Poly1305::seal(rng, key, plaintext, associated_data).unwrap();

                let ephemeral = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                    &raw.ephemeral_public_key,
                )
                .unwrap();
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::K256XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                    nonce: raw.nonce,
                })
            },
        }
    }

    /// Get algorithm identifier for this sealing key
    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            SealingKey::K256XChaCha20Poly1305(_) => CryptoAlgorithm::K256XChaCha20Poly1305,
        }
    }
}

/// Secret key for unsealing messages
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::SecretKey),
}

impl UnsealingKey {
    /// Unseal a sealed message
    pub fn unseal(
        &self,
        sealed_message: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        // Check algorithm compatibility
        let compatible = match (self, &sealed_message.ephemeral_key) {
            (
                UnsealingKey::K256XChaCha20Poly1305(_),
                EphemeralPublicKey::K256XChaCha20Poly1305(_),
            ) => true,
        };

        if !compatible {
            return Err(IntegratedEncryptionSchemeError::AlgorithmMismatch);
        }

        // Convert to internal format and delegate
        let raw_sealed = RawSealedMessage {
            ephemeral_public_key: sealed_message.ephemeral_key.to_bytes(),
            nonce: sealed_message.nonce.clone(),
            ciphertext: sealed_message.ciphertext.to_vec(),
        };

        match self {
            UnsealingKey::K256XChaCha20Poly1305(key) => {
                K256XChaCha20Poly1305::unseal(key, &raw_sealed, associated_data)
            },
        }
    }

    /// Get algorithm identifier for this secret key
    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => CryptoAlgorithm::K256XChaCha20Poly1305,
        }
    }

    /// Get algorithm name for this secret key
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }
}

/// Ephemeral public key, part of sealed messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EphemeralPublicKey {
    K256XChaCha20Poly1305(ecdh::EphemeralPublicKey),
}

impl EphemeralPublicKey {
    /// Get algorithm identifier for this ephemeral key
    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => CryptoAlgorithm::K256XChaCha20Poly1305,
        }
    }

    /// Get algorithm name for this ephemeral key
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(key) => key.to_bytes(),
        }
    }

    /// Deserialize from bytes with explicit algorithm
    pub fn from_bytes(
        algorithm: CryptoAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, IntegratedEncryptionSchemeError> {
        match algorithm {
            CryptoAlgorithm::K256XChaCha20Poly1305 => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .unwrap();
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
        }
    }
}

// SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let algorithm = self.algorithm();
        target.write_u8(algorithm as u8);

        let eph_key_bytes = self.ephemeral_key.to_bytes();
        target.write_usize(eph_key_bytes.len());
        target.write_bytes(&eph_key_bytes);

        target.write_usize(self.ciphertext.len());
        target.write_bytes(&self.ciphertext);

        target.write_usize(self.nonce.len());
        target.write_bytes(&self.nonce);
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let algorithm = source.read_u8()?;
        let algorithm = CryptoAlgorithm::from_u8(algorithm).unwrap();

        let eph_key_len = source.read_usize()?;
        let eph_key_bytes = source.read_vec(eph_key_len)?;
        let ephemeral_key = EphemeralPublicKey::from_bytes(algorithm, &eph_key_bytes).unwrap();

        let ciphertext_len = source.read_usize()?;
        let ciphertext = source.read_vec(ciphertext_len)?;

        let nonce_len = source.read_usize()?;
        let nonce = source.read_vec(nonce_len)?;

        Ok(Self { ephemeral_key, ciphertext, nonce })
    }
}

// ERROR TYPES
// ================================================================================================

#[derive(Debug)]
pub enum IntegratedEncryptionSchemeError {
    KeyAgreementFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    InvalidNonce,
    EphemeralPublicKeyDeserializationFailed,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
}

impl fmt::Display for IntegratedEncryptionSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegratedEncryptionSchemeError::KeyAgreementFailed => {
                write!(f, "key agreement failed")
            },
            IntegratedEncryptionSchemeError::EncryptionFailed => write!(f, "encryption failed"),
            IntegratedEncryptionSchemeError::DecryptionFailed => write!(f, "decryption failed"),
            IntegratedEncryptionSchemeError::InvalidKeySize => write!(f, "invalid key size"),
            IntegratedEncryptionSchemeError::InvalidNonce => write!(f, "invalid nonce"),
            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed => {
                write!(f, "ephemeral public key deserialization failed")
            },
            IntegratedEncryptionSchemeError::AlgorithmMismatch => write!(f, "algorithm mismatch"),
            IntegratedEncryptionSchemeError::UnsupportedAlgorithm => {
                write!(f, "unsupported algorithm")
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::ecdsa_k256_keccak::SecretKey;

    #[test]
    fn test_all_algorithms() {
        let mut rng = rand::rng();
        let plaintext = b"Hello, Miden Crypto!";
        let associated_data = b"test-context";

        let secret_key = SecretKey::new();
        let public_key = secret_key.public_key();

        // Seal message
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal(&mut rng, plaintext, associated_data).unwrap();

        // Verify algorithm consistency
        assert_eq!(sealing_key.algorithm(), sealed.algorithm());

        let sealed_serialized = sealed.to_bytes();
        let sealed_deserialized = SealedMessage::read_from_bytes(&sealed_serialized).unwrap();
        assert_eq!(sealed_deserialized, sealed);

        // Unseal message
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let decrypted = unsealing_key.unseal(&sealed, associated_data).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
