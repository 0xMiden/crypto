use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::{
    crypto_box::CryptoBox,
    error::IesError,
    message::{IesScheme, SealedMessage},
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
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seal (encrypt and authenticate) data for this recipient given some associated data
        pub fn seal_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<SealedMessage, IesError> {
            match self {
                $(
                    $variant(key) => {
                        let (ciphertext, ephemeral) = <$crypto_box>::seal_bytes_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates seal_elements_with_associated_data method implementation
macro_rules! impl_seal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seal field elements with associated data for this recipient
        pub fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[Felt],
            associated_data: &[Felt],
        ) -> Result<SealedMessage, IesError> {
            match self {
                $(
                    $variant(key) => {
                        let (ciphertext, ephemeral) = <$crypto_box>::seal_elements_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates unseal_with_associated_data method implementation
macro_rules! impl_unseal_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Unseal a sealed message given its associated data
        pub fn unseal_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[u8],
        ) -> Result<Vec<u8>, IesError> {
            // Check scheme compatibility using constant-time comparison
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.ephemeral_key.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { ephemeral_key, ciphertext } = sealed_message;

            match (self, ephemeral_key) {
                $(
                    ($variant(key), $ephemeral_variant(ephemeral)) => {
                        <$crypto_box>::unseal_bytes_with_associated_data(key, &ephemeral, &ciphertext, associated_data)
                    }
                )*
                _ => Err(IesError::SchemeMismatch),
            }
        }
    };
}

/// Generates unseal_elements_with_associated_data method implementation
macro_rules! impl_unseal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Unseal field elements from a sealed message with associated data
        pub fn unseal_elements_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[Felt],
        ) -> Result<Vec<Felt>, IesError> {
            // Check scheme compatibility
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.ephemeral_key.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { ephemeral_key, ciphertext } = sealed_message;

            match (self, ephemeral_key) {
                $(
                    ($variant(key), $ephemeral_variant(ephemeral)) => {
                        <$crypto_box>::unseal_elements_with_associated_data(key, &ephemeral, &ciphertext, associated_data)
                    }
                )*
                _ => Err(IesError::SchemeMismatch),
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
    ) -> Result<SealedMessage, IesError> {
        self.seal_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        SealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
    }

    /// Seal field elements for this recipient (only available for X25519Rpo256)
    pub fn seal_elements<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[Felt],
    ) -> Result<SealedMessage, IesError> {
        self.seal_elements_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_elements_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        SealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
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
    pub fn unseal(&self, sealed_message: SealedMessage) -> Result<Vec<u8>, IesError> {
        self.unseal_with_associated_data(sealed_message, &[])
    }

    impl_unseal_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        UnsealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
    }

    /// Get scheme identifier for this secret key
    fn scheme(&self) -> IesScheme {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            UnsealingKey::K256AeadRpo(_) => IesScheme::K256AeadRpo,
            UnsealingKey::X25519AeadRpo(_) => IesScheme::X25519AeadRpo,
        }
    }

    /// Get scheme name for this secret key
    pub fn scheme_name(&self) -> &'static str {
        self.scheme().name()
    }

    /// Unseal field elements from a sealed message (only available for X25519Rpo256)
    pub fn unseal_elements(&self, sealed_message: SealedMessage) -> Result<Vec<Felt>, IesError> {
        self.unseal_elements_with_associated_data(sealed_message, &[])
    }

    impl_unseal_elements_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        UnsealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
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
    /// Get scheme identifier for this ephemeral key
    pub fn scheme(&self) -> IesScheme {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            EphemeralPublicKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            EphemeralPublicKey::K256AeadRpo(_) => IesScheme::K256AeadRpo,
            EphemeralPublicKey::X25519AeadRpo(_) => IesScheme::X25519AeadRpo,
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

    /// Deserialize from bytes with explicit scheme
    pub fn from_bytes(scheme: IesScheme, bytes: &[u8]) -> Result<Self, IesError> {
        match scheme {
            IesScheme::K256XChaCha20Poly1305 | IesScheme::K256AeadRpo => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
            IesScheme::X25519XChaCha20Poly1305 | IesScheme::X25519AeadRpo => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::X25519XChaCha20Poly1305(key))
            },
        }
    }
}
