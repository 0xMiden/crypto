//! Core cryptographic primitive for Integrated Encryption Scheme (IES).
//!
//! This module defines the generic `CryptoBox` abstraction that combines a key agreement scheme
//! (e.g. K256 ECDH) with an AEAD scheme (e.g. XChaCha20-Poly1305) to provide authenticated
//! encryption.

use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use super::IesError;
use crate::{Felt, aead::AeadScheme, ecdh::KeyAgreementScheme, zeroize::Zeroizing};

// CRYPTO BOX
// ================================================================================================

/// A generic CryptoBox primitive parameterized by key agreement and AEAD schemes.
pub(super) struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

impl<K: KeyAgreementScheme, A: AeadScheme> CryptoBox<K, A> {
    // BYTE-SPECIFIC METHODS
    // --------------------------------------------------------------------------------------------

    pub fn seal_bytes_with_associated_data<R: CryptoRng + RngCore>(
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

    pub fn unseal_bytes_with_associated_data(
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

        A::decrypt_bytes_with_associated_data(&decryption_key, ciphertext, associated_data)
            .map_err(|_| IesError::DecryptionFailed)
    }

    // ELEMENT-SPECIFIC METHODS
    // --------------------------------------------------------------------------------------------

    pub fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
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

    pub fn unseal_elements_with_associated_data(
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

        A::decrypt_elements_with_associated_data(&decryption_key, ciphertext, associated_data)
            .map_err(|_| IesError::DecryptionFailed)
    }
}
