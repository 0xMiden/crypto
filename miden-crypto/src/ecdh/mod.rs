//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, RngCore};
use winter_utils::{Deserializable, Serializable};
use zeroize::Zeroize;

mod k256;
pub use k256::{EphemeralPublicKey, EphemeralSecretKey, K256, SharedSecret};

// KEY AGREEMENT TRAIT
// ================================================================================================

pub trait KeyAgreementScheme {
    type EphemeralSecretKey: Zeroize;
    type EphemeralPublicKey: Serializable + Deserializable;

    type SecretKey;
    type PublicKey: Clone;

    type SharedSecret: Zeroize + AsRef<[u8]>;

    fn generate_ephemeral_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (Self::EphemeralSecretKey, Self::EphemeralPublicKey);

    /// Perform key exchange between ephemeral secret and static public key
    fn exchange_ephemeral_static(
        ephemeral_sk: &Self::EphemeralSecretKey,
        static_pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Perform key exchange between static secret and ephemeral public key
    fn exchange_static_ephemeral(
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Extract key material from shared secret
    fn extract_key_material(shared_secret: &Self::SharedSecret, length: usize) -> Vec<u8>;
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug)]
pub enum KeyAgreementError {
    FailedKeyAgreement,
    PublicKeyDeserializationFailed,
}

impl fmt::Display for KeyAgreementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAgreementError::FailedKeyAgreement => {
                write!(f, "key agreement failed")
            },
            KeyAgreementError::PublicKeyDeserializationFailed => {
                write!(f, "deserialization of public key failed")
            },
        }
    }
}

impl core::error::Error for KeyAgreementError {}
