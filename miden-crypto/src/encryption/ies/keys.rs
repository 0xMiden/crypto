use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::{
    crypto_box::{CryptoBox, RawSealedMessage},
    error::IntegratedEncryptionSchemeError,
    message::{CryptoAlgorithm, SealedMessage},
};
use crate::{
    ecdh::{KeyAgreementScheme, k256::K256},
    encryption::xchacha::XChaCha,
    utils::{Deserializable, Serializable},
};

/// Instantiation of sealed box using K256 + XChaCha20Poly1305
type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;

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
                let raw = K256XChaCha20Poly1305::seal(rng, key, plaintext, associated_data)?;

                let ephemeral = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                    &raw.ephemeral_public_key,
                )
                .map_err(|_| {
                    IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                })?;
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::K256XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                    nonce: raw.nonce,
                })
            },
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
        sealed_message: SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        // Check algorithm compatibility using constant-time comparison
        let self_algo = self.algorithm() as u8;
        let msg_algo = sealed_message.ephemeral_key.algorithm() as u8;

        let compatible = self_algo == msg_algo;
        if !compatible {
            return Err(IntegratedEncryptionSchemeError::AlgorithmMismatch);
        }

        // Destructure and serialize the ephemeral key
        let SealedMessage { ephemeral_key, ciphertext, nonce } = sealed_message;
        let raw_sealed = RawSealedMessage {
            ephemeral_public_key: ephemeral_key.to_bytes(),
            nonce,
            ciphertext,
        };

        match self {
            UnsealingKey::K256XChaCha20Poly1305(key) => {
                K256XChaCha20Poly1305::unseal(key, &raw_sealed, associated_data)
            },
        }
    }

    /// Get algorithm identifier for this secret key
    fn algorithm(&self) -> CryptoAlgorithm {
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
pub(crate) enum EphemeralPublicKey {
    K256XChaCha20Poly1305(crate::ecdh::k256::EphemeralPublicKey),
}

impl EphemeralPublicKey {
    /// Get algorithm identifier for this ephemeral key
    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => CryptoAlgorithm::K256XChaCha20Poly1305,
        }
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
                    .map_err(|_| {
                        IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                    })?;
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
    fn test_sealing_and_unsealing_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"roundtrip";
        let ad = b"ctx";

        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let decrypted = unsealing_key.unseal(sealed, ad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"with ad";
        let ad = b"good";
        let bad_ad = b"bad";

        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let result = unsealing_key.unseal(sealed, bad_ad);

        assert!(result.is_err());
    }
}
