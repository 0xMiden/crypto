use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::{
    crypto_box::{CryptoBox, RawSealedMessage},
    error::IntegratedEncryptionSchemeError,
    message::{IesAlgorithm, SealedMessage},
};
use crate::{
    aead::xchacha::XChaCha,
    ecdh::{KeyAgreementScheme, k256::K256, x25519::X25519},
    utils::{Deserializable, Serializable},
};

/// Instantiation of sealed box using K256 + XChaCha20Poly1305
type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;
/// Instantiation of sealed box using X25519 + XChaCha20Poly1305
type X25519XChaCha20Poly1305 = CryptoBox<X25519, XChaCha>;

/// Public key for sealing messages to a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::PublicKey),
}

impl SealingKey {
    /// Seal (encrypt and authenticate) data for this recipient
    pub fn seal<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
        match self {
            SealingKey::K256XChaCha20Poly1305(key) => {
                let raw = K256XChaCha20Poly1305::seal(rng, key, plaintext)?;

                let ephemeral = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                    &raw.ephemeral_public_key,
                )
                .map_err(|_| {
                    IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                })?;
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::K256XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                })
            },
            SealingKey::X25519XChaCha20Poly1305(key) => {
                let raw = X25519XChaCha20Poly1305::seal(rng, key, plaintext)?;
                let ephemeral =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                        &raw.ephemeral_public_key,
                    )
                    .map_err(|_| {
                        IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                    })?;
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::X25519XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                })
            },
        }
    }

    /// Seal (encrypt and authenticate) data for this recipient given some associated data
    pub fn seal_with_associated_data<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
        match self {
            SealingKey::K256XChaCha20Poly1305(key) => {
                let raw = K256XChaCha20Poly1305::seal_with_associated_data(
                    rng,
                    key,
                    plaintext,
                    associated_data,
                )?;

                let ephemeral = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                    &raw.ephemeral_public_key,
                )
                .map_err(|_| {
                    IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                })?;
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::K256XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                })
            },
            SealingKey::X25519XChaCha20Poly1305(key) => {
                let raw = X25519XChaCha20Poly1305::seal_with_associated_data(
                    rng,
                    key,
                    plaintext,
                    associated_data,
                )?;
                let ephemeral =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                        &raw.ephemeral_public_key,
                    )
                    .map_err(|_| {
                        IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                    })?;
                Ok(SealedMessage {
                    ephemeral_key: EphemeralPublicKey::X25519XChaCha20Poly1305(ephemeral),
                    ciphertext: raw.ciphertext,
                })
            },
        }
    }
}

/// Secret key for unsealing messages
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::SecretKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::SecretKey),
}

impl UnsealingKey {
    /// Unseal a sealed message
    pub fn unseal(
        &self,
        sealed_message: SealedMessage,
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        // Check algorithm compatibility using constant-time comparison
        let self_algo = self.algorithm() as u8;
        let msg_algo = sealed_message.ephemeral_key.algorithm() as u8;

        let compatible = self_algo == msg_algo;
        if !compatible {
            return Err(IntegratedEncryptionSchemeError::AlgorithmMismatch);
        }

        // Destructure and serialize the ephemeral key
        let SealedMessage { ephemeral_key, ciphertext } = sealed_message;
        let raw_sealed = RawSealedMessage {
            ephemeral_public_key: ephemeral_key.to_bytes(),
            ciphertext,
        };

        match self {
            UnsealingKey::K256XChaCha20Poly1305(key) => {
                K256XChaCha20Poly1305::unseal(key, &raw_sealed)
            },
            UnsealingKey::X25519XChaCha20Poly1305(key) => {
                X25519XChaCha20Poly1305::unseal(key, &raw_sealed)
            },
        }
    }

    /// Unseal a sealed message given its associated data
    pub fn unseal_with_associated_data(
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
        let SealedMessage { ephemeral_key, ciphertext } = sealed_message;
        let raw_sealed = RawSealedMessage {
            ephemeral_public_key: ephemeral_key.to_bytes(),
            ciphertext,
        };

        match self {
            UnsealingKey::K256XChaCha20Poly1305(key) => {
                K256XChaCha20Poly1305::unseal_with_associated_data(
                    key,
                    &raw_sealed,
                    associated_data,
                )
            },
            UnsealingKey::X25519XChaCha20Poly1305(key) => {
                X25519XChaCha20Poly1305::unseal_with_associated_data(
                    key,
                    &raw_sealed,
                    associated_data,
                )
            },
        }
    }

    /// Get algorithm identifier for this secret key
    fn algorithm(&self) -> IesAlgorithm {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesAlgorithm::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesAlgorithm::X25519XChaCha20Poly1305,
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
    X25519XChaCha20Poly1305(crate::ecdh::x25519::EphemeralPublicKey),
}

impl EphemeralPublicKey {
    /// Get algorithm identifier for this ephemeral key
    pub fn algorithm(&self) -> IesAlgorithm {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => IesAlgorithm::K256XChaCha20Poly1305,
            EphemeralPublicKey::X25519XChaCha20Poly1305(_) => IesAlgorithm::X25519XChaCha20Poly1305,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(key) => key.to_bytes(),
            EphemeralPublicKey::X25519XChaCha20Poly1305(key) => key.to_bytes(),
        }
    }

    /// Deserialize from bytes with explicit algorithm
    pub fn from_bytes(
        algorithm: IesAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, IntegratedEncryptionSchemeError> {
        match algorithm {
            IesAlgorithm::K256XChaCha20Poly1305 => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .map_err(|_| {
                        IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                    })?;
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
            IesAlgorithm::X25519XChaCha20Poly1305 => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                        .map_err(|_| {
                            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                        })?;
                Ok(EphemeralPublicKey::X25519XChaCha20Poly1305(key))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::{ecdsa_k256_keccak::SecretKey, eddsa_25519::SecretKey as SecretKey25519};

    #[test]
    fn test_sealing_and_unsealing_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"roundtrip";
        let ad = b"ctx";

        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let decrypted = unsealing_key.unseal_with_associated_data(sealed, ad).unwrap();

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
        let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let result = unsealing_key.unseal_with_associated_data(sealed, bad_ad);

        assert!(result.is_err());
    }

    #[test]
    fn test_sealing_and_unsealing_roundtrip_x25519() {
        let mut rng = rand::rng();
        let plaintext = b"roundtrip-x25519";
        let ad = b"ctx-x25519";

        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let decrypted = unsealing_key.unseal_with_associated_data(sealed, ad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_associated_data_x25519() {
        let mut rng = rand::rng();
        let plaintext = b"with ad x25519";
        let ad = b"good-x25519";
        let bad_ad = b"bad-x25519";

        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let result = unsealing_key.unseal_with_associated_data(sealed, bad_ad);

        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_public_key_serialization_roundtrip_k256() {
        let mut rng = rand::rng();
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, b"msg", b"ad").unwrap();

        let original = sealed.ephemeral_key.clone();
        let bytes = original.to_bytes();
        let restored = EphemeralPublicKey::from_bytes(original.algorithm(), &bytes).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_ephemeral_public_key_serialization_roundtrip_x25519() {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, b"msg", b"ad").unwrap();

        let original = sealed.ephemeral_key.clone();
        let bytes = original.to_bytes();
        let restored = EphemeralPublicKey::from_bytes(original.algorithm(), &bytes).unwrap();

        assert_eq!(original, restored);
    }
}
