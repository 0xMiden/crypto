use rand::{CryptoRng, RngCore};

use alloc::vec::Vec;
use winter_utils::Serializable;

use crate::{
    ecdh::K256, ecdh::KeyAgreementScheme, encryption::xchacha::XChaCha, utils::Deserializable,
};

use super::crypto_box::{CryptoBox, RawSealedMessage};
use super::error::IntegratedEncryptionSchemeError;
use super::message::{CryptoAlgorithm, SealedMessage};

/// A CryptoBox instantiation: K256 + XChaCha20Poly1305
pub type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;

/// Public key for sealing messages to a recipient.
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
    K256XChaCha20Poly1305(crate::ecdh::EphemeralPublicKey),
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
