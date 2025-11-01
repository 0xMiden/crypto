use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::{IesError, IesScheme, crypto_box::CryptoBox, message::SealedMessage};
use crate::{
    Felt,
    aead::{aead_rpo::AeadRpo, xchacha::XChaCha},
    ecdh::{KeyAgreementScheme, k256::K256, x25519::X25519},
    utils::{Deserializable, Serializable},
};

// TYPE ALIASES
// ================================================================================================

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

/// Generates seal_bytes_with_associated_data method implementation
macro_rules! impl_seal_bytes_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seals the provided plaintext (represented as bytes) and associated data with this
        /// sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
        pub fn seal_bytes_with_associated_data<R: CryptoRng + RngCore>(
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
        /// Seals the provided plaintext (represented as filed elements) and associated data with
        /// this sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
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

/// Generates unseal_bytes_with_associated_data method implementation
macro_rules! impl_unseal_bytes_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Unseals the provided message using this unsealing key and returns the plaintext as bytes.
        ///
        /// # Errors
        /// Returns an error if:
        /// - The message was not sealed as bytes (i.e., if it was sealed using `seal_elements()`
        ///   or `seal_elements_with_associated_data()`)
        /// - The scheme used to seal the message does not match this unsealing key's scheme
        /// - Decryption or authentication fails
        pub fn unseal_bytes_with_associated_data(
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
        /// Unseals the provided message using this unsealing key and returns the plaintext as field elements.
        ///
        /// # Errors
        /// Returns an error if:
        /// - The message was not sealed as elements (i.e., if it was sealed using `seal_bytes()`
        ///   or `seal_bytes_with_associated_data()`)
        /// - The scheme used to seal the message does not match this unsealing key's scheme
        /// - Decryption or authentication fails
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

// SEALING KEY
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
    /// Seals the provided plaintext (represented as bytes) with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
    pub fn seal_bytes<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<SealedMessage, IesError> {
        self.seal_bytes_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_bytes_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        SealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
    }

    /// Seals the provided plaintext (represented as filed elements) with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
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

// UNSEALING KEY
// ================================================================================================

/// Secret key for unsealing messages.
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::SecretKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::SecretKey),
    K256AeadRpo(crate::dsa::ecdsa_k256_keccak::SecretKey),
    X25519AeadRpo(crate::dsa::eddsa_25519::SecretKey),
}

impl UnsealingKey {
    /// Returns scheme identifier for this unsealing key.
    fn scheme(&self) -> IesScheme {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            UnsealingKey::K256AeadRpo(_) => IesScheme::K256AeadRpo,
            UnsealingKey::X25519AeadRpo(_) => IesScheme::X25519AeadRpo,
        }
    }

    /// Returns scheme name for this unsealing key.
    pub fn scheme_name(&self) -> &'static str {
        self.scheme().name()
    }

    /// Unseals the provided message using this unsealing key.
    ///
    /// The message must have been sealed as bytes (i.e., using `seal_bytes()` or
    /// `seal_bytes_with_associated_data()` method), otherwise an error will be returned.
    pub fn unseal_bytes(&self, sealed_message: SealedMessage) -> Result<Vec<u8>, IesError> {
        self.unseal_bytes_with_associated_data(sealed_message, &[])
    }

    impl_unseal_bytes_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadRpo => K256AeadRpo, EphemeralPublicKey::K256AeadRpo;
        UnsealingKey::X25519AeadRpo => X25519AeadRpo, EphemeralPublicKey::X25519AeadRpo;
    }

    /// Unseals the provided message using this unsealing key.
    ///
    /// The message must have been sealed as elements (i.e., using `seal_elements()` or
    /// `seal_elements_with_associated_data()` method), otherwise an error will be returned.
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

// EPHEMERAL PUBLIC KEY
// ================================================================================================

/// Ephemeral public key, part of sealed messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EphemeralPublicKey {
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
            IesScheme::K256XChaCha20Poly1305 => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
            IesScheme::K256AeadRpo => {
                let key = <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::K256AeadRpo(key))
            },
            IesScheme::X25519XChaCha20Poly1305 => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::X25519XChaCha20Poly1305(key))
            },
            IesScheme::X25519AeadRpo => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(bytes)
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::X25519AeadRpo(key))
            },
        }
    }
}
