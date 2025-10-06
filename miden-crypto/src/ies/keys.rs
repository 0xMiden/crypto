use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::{
    crypto_box::{CryptoBox, RawSealedMessage},
    error::IntegratedEncryptionSchemeError,
    message::{IesAlgorithm, SealedMessage},
};
use crate::{
    Felt,
    aead::{aead_rpo::AeadRpo, xchacha::XChaCha},
    ecdh::{KeyAgreementScheme, k256::K256, x25519::X25519},
    utils::{Deserializable, Serializable},
};

/// Instantiation of sealed box using K256 + XChaCha20Poly1305
type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;
/// Instantiation of sealed box using X25519 + XChaCha20Poly1305
type X25519XChaCha20Poly1305 = CryptoBox<X25519, XChaCha>;
/// Instantiation of sealed box using K256 + AeadRPO
type K256AeadRpo = CryptoBox<K256, AeadRpo>;
/// Instantiation of sealed box using X25519 + AeadRPO
type X25519AeadRpo = CryptoBox<X25519, AeadRpo>;

// HELPER MACROS
// ================================================================================================

/// Generates seal_with_associated_data method implementation
macro_rules! impl_seal_with_associated_data {
    ($($variant:path => $crypto_box:ty, $key_agreement:ty, $ephemeral_variant:path;)*) => {
        /// Seal (encrypt and authenticate) data for this recipient given some associated data
        pub fn seal_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        let raw = <$crypto_box>::seal_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        let ephemeral = <$key_agreement as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                            &raw.ephemeral_public_key,
                        )
                        .map_err(|_| {
                            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                        })?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext: raw.ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates seal_elements_with_associated_data method implementation
macro_rules! impl_seal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $key_agreement:ty, $ephemeral_variant:path;)*) => {
        /// Seal field elements with associated data for this recipient
        pub fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[Felt],
            associated_data: &[Felt],
        ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        let raw = <$crypto_box>::seal_elements_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        let ephemeral = <$key_agreement as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                            &raw.ephemeral_public_key,
                        )
                        .map_err(|_| {
                            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                        })?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext: raw.ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates unseal_with_associated_data method implementation
macro_rules! impl_unseal_with_associated_data {
    ($($variant:path => $crypto_box:ty;)*) => {
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
                $(
                    $variant(key) => {
                        <$crypto_box>::unseal_with_associated_data(key, &raw_sealed, associated_data)
                    }
                )*
            }
        }
    };
}

/// Generates unseal_elements_with_associated_data method implementation
macro_rules! impl_unseal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty;)*) => {
        /// Unseal field elements from a sealed message with associated data
        pub fn unseal_elements_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[Felt],
        ) -> Result<Vec<Felt>, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        // Check algorithm compatibility
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

                        <$crypto_box>::unseal_elements_with_associated_data(key, &raw_sealed, associated_data)
                    }
                )*
            }
        }
    };
}

// STRUCTS AND IMPLEMENTATIONS
// ================================================================================================

/// Public key for sealing messages to a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::PublicKey),
    K256AeadRpo(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519AeadRpo(crate::dsa::eddsa_25519::PublicKey),
}

impl SealingKey {
    /// Seal (encrypt and authenticate) data for this recipient
    pub fn seal<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
        self.seal_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, K256, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, X25519, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadRpo => K256AeadRpo, K256, EphemeralPublicKey::K256AeadRpo;
        SealingKey::X25519AeadRpo => X25519AeadRpo, X25519, EphemeralPublicKey::X25519AeadRpo;
    }

    /// Seal field elements for this recipient (only available for X25519Rpo256)
    pub fn seal_elements<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[Felt],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
        self.seal_elements_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_elements_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, K256, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, X25519, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadRpo => K256AeadRpo, K256, EphemeralPublicKey::K256AeadRpo;
        SealingKey::X25519AeadRpo => X25519AeadRpo, X25519, EphemeralPublicKey::X25519AeadRpo;
    }
}

/// Secret key for unsealing messages
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::SecretKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::SecretKey),
    K256AeadRpo(crate::dsa::ecdsa_k256_keccak::SecretKey),
    X25519AeadRpo(crate::dsa::eddsa_25519::SecretKey),
}

impl UnsealingKey {
    /// Unseal a sealed message
    pub fn unseal(
        &self,
        sealed_message: SealedMessage,
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        self.unseal_with_associated_data(sealed_message, &[])
    }

    impl_unseal_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadRpo => K256AeadRpo;
        UnsealingKey::X25519AeadRpo => X25519AeadRpo;
    }

    /// Get algorithm identifier for this secret key
    fn algorithm(&self) -> IesAlgorithm {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesAlgorithm::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesAlgorithm::X25519XChaCha20Poly1305,
            UnsealingKey::K256AeadRpo(_) => IesAlgorithm::K256AeadRpo,
            UnsealingKey::X25519AeadRpo(_) => IesAlgorithm::X25519AeadRpo,
        }
    }

    /// Get algorithm name for this secret key
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }

    /// Unseal field elements from a sealed message (only available for X25519Rpo256)
    pub fn unseal_elements(
        &self,
        sealed_message: SealedMessage,
    ) -> Result<Vec<Felt>, IntegratedEncryptionSchemeError> {
        self.unseal_elements_with_associated_data(sealed_message, &[])
    }

    impl_unseal_elements_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadRpo => K256AeadRpo;
        UnsealingKey::X25519AeadRpo => X25519AeadRpo;
    }
}

/// Ephemeral public key, part of sealed messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EphemeralPublicKey {
    K256XChaCha20Poly1305(crate::ecdh::k256::EphemeralPublicKey),
    X25519XChaCha20Poly1305(crate::ecdh::x25519::EphemeralPublicKey),
    K256AeadRpo(crate::ecdh::k256::EphemeralPublicKey),
    X25519AeadRpo(crate::ecdh::x25519::EphemeralPublicKey),
}

impl EphemeralPublicKey {
    /// Get algorithm identifier for this ephemeral key
    pub fn algorithm(&self) -> IesAlgorithm {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => IesAlgorithm::K256XChaCha20Poly1305,
            EphemeralPublicKey::X25519XChaCha20Poly1305(_) => IesAlgorithm::X25519XChaCha20Poly1305,
            EphemeralPublicKey::K256AeadRpo(_) => IesAlgorithm::K256AeadRpo,
            EphemeralPublicKey::X25519AeadRpo(_) => IesAlgorithm::X25519AeadRpo,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(key) => key.to_bytes(),
            EphemeralPublicKey::X25519XChaCha20Poly1305(key) => key.to_bytes(),
            EphemeralPublicKey::K256AeadRpo(key) => key.to_bytes(),
            EphemeralPublicKey::X25519AeadRpo(key) => key.to_bytes(),
        }
    }

    /// Deserialize from bytes with explicit algorithm
    pub fn from_bytes(
        algorithm: IesAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, IntegratedEncryptionSchemeError> {
        match algorithm {
            IesAlgorithm::K256XChaCha20Poly1305 | IesAlgorithm::K256AeadRpo => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .map_err(|_| {
                        IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                    })?;
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
            IesAlgorithm::X25519XChaCha20Poly1305 | IesAlgorithm::X25519AeadRpo => {
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
