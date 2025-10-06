//! Core cryptographic primitive for Integrated Encryption Scheme (IES).
//!
//! This module defines the generic `CryptoBox` abstraction that combines a key agreement scheme
//! (e.g. K256 ECDH) with an AEAD scheme (e.g. XChaCha20-Poly1305) to provide authenticated
//! encryption.
//!
//! It also defines the `RawSealedMessage` which carries ephemeral keys, nonce, and ciphertext
//! in raw form.

use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::error::IntegratedEncryptionSchemeError;
use crate::{
    Felt,
    aead::AeadScheme,
    ecdh::KeyAgreementScheme,
    utils::{Deserializable, Serializable},
};

/// A generic CryptoBox primitive parameterized by key agreement and AEAD schemes
pub(crate) struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

/// Internal raw sealed message representation
#[derive(Debug)]
pub(crate) struct RawSealedMessage {
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl<K: KeyAgreementScheme, A: AeadScheme> CryptoBox<K, A> {
    // BYTE-SPECIFIC METHODS
    // ================================================================================================

    pub(crate) fn seal_with_associated_data<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RawSealedMessage, IntegratedEncryptionSchemeError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
            .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?);

        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&*shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?
        );

        let encryption_key = Zeroizing::new(A::key_from_bytes(&*encryption_key_bytes)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?);

        let ciphertext = A::encrypt_bytes(&*encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionFailed)?;

        Ok(RawSealedMessage {
            ciphertext,
            ephemeral_public_key: ephemeral_public.to_bytes(),
        })
    }

    pub(crate) fn unseal_with_associated_data(
        recipient_private_key: &K::SecretKey,
        sealed_message: &RawSealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        let ephemeral_public = K::EphemeralPublicKey::read_from_bytes(
            &sealed_message.ephemeral_public_key,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed)?;

        let shared_secret = Zeroizing::new(K::exchange_static_ephemeral(recipient_private_key, &ephemeral_public)
            .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?);

        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&*shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?
        );

        let decryption_key = Zeroizing::new(A::key_from_bytes(&*decryption_key_bytes)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?);

        let result = A::decrypt_bytes_with_associated_data(
            &*decryption_key,
            &sealed_message.ciphertext,
            associated_data,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?;

        Ok(result)
    }

    // FELT-SPECIFIC METHODS
    // ================================================================================================

    /// Seals field elements with associated data using authenticated encryption.
    pub(crate) fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<RawSealedMessage, IntegratedEncryptionSchemeError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
            .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?);

        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&*shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?
        );

        let encryption_key = Zeroizing::new(A::key_from_bytes(&*encryption_key_bytes)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?);

        let ciphertext = A::encrypt_elements(&*encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionFailed)?;

        Ok(RawSealedMessage {
            ciphertext,
            ephemeral_public_key: ephemeral_public.to_bytes(),
        })
    }

    /// Unseals field elements from a sealed message with associated data.
    pub(crate) fn unseal_elements_with_associated_data(
        recipient_private_key: &K::SecretKey,
        sealed_message: &RawSealedMessage,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IntegratedEncryptionSchemeError> {
        let ephemeral_public = K::EphemeralPublicKey::read_from_bytes(
            &sealed_message.ephemeral_public_key,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed)?;

        let shared_secret = Zeroizing::new(K::exchange_static_ephemeral(recipient_private_key, &ephemeral_public)
            .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?);

        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&*shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?
        );

        let decryption_key = Zeroizing::new(A::key_from_bytes(&*decryption_key_bytes)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?);

        let result = A::decrypt_elements_with_associated_data(
            &*decryption_key,
            &sealed_message.ciphertext,
            associated_data,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?;

        Ok(result)
    }
}
