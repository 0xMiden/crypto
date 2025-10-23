//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};
use thiserror::Error;
use winter_utils::{Deserializable, Serializable};

use crate::zeroize::{Zeroize, ZeroizeOnDrop};

pub mod k256;
pub mod x25519;

// KEY AGREEMENT TRAIT
// ================================================================================================

pub trait KeyAgreementScheme {
    type EphemeralSecretKey: ZeroizeOnDrop;
    type EphemeralPublicKey: Serializable + Deserializable;

    type SecretKey;
    type PublicKey: Clone;

    type SharedSecret: AsRef<[u8]> + Zeroize + ZeroizeOnDrop;

    fn generate_ephemeral_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (Self::EphemeralSecretKey, Self::EphemeralPublicKey);

    /// Perform key exchange between ephemeral secret and static public key
    fn exchange_ephemeral_static(
        ephemeral_sk: Self::EphemeralSecretKey,
        static_pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Perform key exchange between static secret and ephemeral public key
    fn exchange_static_ephemeral(
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Extract key material from shared secret
    fn extract_key_material(
        shared_secret: &Self::SharedSecret,
        length: usize,
    ) -> Result<Vec<u8>, KeyAgreementError>;
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub enum KeyAgreementError {
    #[error("key agreement failed")]
    FailedKeyAgreement,
    #[error("deserialization of public key failed")]
    PublicKeyDeserializationFailed,
    #[error("hkdf expansion failed")]
    HkdfExpansionFailed,
}
