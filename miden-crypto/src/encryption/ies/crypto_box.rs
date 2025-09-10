//! Core cryptographic primitive for Integrated Encryption Scheme (IES).
//!
//! This module defines the generic [`CryptoBox`] abstraction that combines a key agreement scheme
//! (e.g. K256 ECDH) with an AEAD scheme (e.g. XChaCha20-Poly1305) to provide authenticated
//! encryption.
//!
//! It also defines the [`RawSealedMessage`] which carries ephemeral keys, nonce, and ciphertext
//! in raw form.

use alloc::vec::Vec;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    ecdh::KeyAgreementScheme,
    encryption::AeadScheme,
    utils::{Deserializable, Serializable},
};

use super::error::IntegratedEncryptionSchemeError;

/// A generic CryptoBox primitive parameterized by KeyAgreement and AEAD schemes
pub struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

/// Internal raw sealed message representation
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
