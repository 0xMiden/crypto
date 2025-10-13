use thiserror::Error;

/// Error type for the Integrated Encryption Scheme (IES)
#[derive(Debug, Error)]
pub enum IesError {
    #[error("key agreement failed")]
    KeyAgreementFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid key size")]
    InvalidKeySize,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("ephemeral public key deserialization failed")]
    EphemeralPublicKeyDeserializationFailed,
    #[error("scheme mismatch")]
    SchemeMismatch,
    #[error("unsupported scheme")]
    UnsupportedScheme,
    #[error("failed to extract key material for encryption/decryption")]
    FailedExtractKeyMaterial,
    #[error("failed to construct the encryption/decryption key from the provided bytes")]
    EncryptionKeyCreationFailed,
}
