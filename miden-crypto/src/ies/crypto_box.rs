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

use super::error::IesError;
use crate::{Felt, aead::AeadScheme, ecdh::KeyAgreementScheme};

/// A generic CryptoBox primitive parameterized by key agreement and AEAD schemes
pub(crate) struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

impl<K: KeyAgreementScheme, A: AeadScheme> CryptoBox<K, A> {
    // BYTE-SPECIFIC METHODS
    // ================================================================================================

    pub(crate) fn seal_bytes_with_associated_data<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, K::EphemeralPublicKey), IesError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            A::key_from_bytes(&encryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = A::encrypt_bytes(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IesError::EncryptionFailed)?;

        Ok((ciphertext, ephemeral_public))
    }

    pub(crate) fn unseal_bytes_with_associated_data(
        recipient_private_key: &K::SecretKey,
        ephemeral_public_key: &K::EphemeralPublicKey,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IesError> {
        let shared_secret = Zeroizing::new(
            K::exchange_static_ephemeral(recipient_private_key, ephemeral_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let decryption_key = Zeroizing::new(
            A::key_from_bytes(&decryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let result =
            A::decrypt_bytes_with_associated_data(&decryption_key, ciphertext, associated_data)
                .map_err(|_| IesError::DecryptionFailed)?;

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
    ) -> Result<(Vec<u8>, K::EphemeralPublicKey), IesError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            A::key_from_bytes(&encryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = A::encrypt_elements(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IesError::EncryptionFailed)?;

        Ok((ciphertext, ephemeral_public))
    }

    /// Unseals field elements from a sealed message with associated data.
    pub(crate) fn unseal_elements_with_associated_data(
        recipient_private_key: &K::SecretKey,
        ephemeral_public_key: &K::EphemeralPublicKey,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IesError> {
        let shared_secret = Zeroizing::new(
            K::exchange_static_ephemeral(recipient_private_key, ephemeral_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let decryption_key = Zeroizing::new(
            A::key_from_bytes(&decryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let result =
            A::decrypt_elements_with_associated_data(&decryption_key, ciphertext, associated_data)
                .map_err(|_| IesError::DecryptionFailed)?;

        Ok(result)
    }
}
