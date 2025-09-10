use core::fmt;

/// Error type for the Integrated Encryption Scheme (IES)
#[derive(Debug)]
pub enum IntegratedEncryptionSchemeError {
    KeyAgreementFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    InvalidNonce,
    EphemeralPublicKeyDeserializationFailed,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
}

impl fmt::Display for IntegratedEncryptionSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegratedEncryptionSchemeError::KeyAgreementFailed => {
                write!(f, "key agreement failed")
            },
            IntegratedEncryptionSchemeError::EncryptionFailed => write!(f, "encryption failed"),
            IntegratedEncryptionSchemeError::DecryptionFailed => write!(f, "decryption failed"),
            IntegratedEncryptionSchemeError::InvalidKeySize => write!(f, "invalid key size"),
            IntegratedEncryptionSchemeError::InvalidNonce => write!(f, "invalid nonce"),
            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed => {
                write!(f, "ephemeral public key deserialization failed")
            },
            IntegratedEncryptionSchemeError::AlgorithmMismatch => write!(f, "algorithm mismatch"),
            IntegratedEncryptionSchemeError::UnsupportedAlgorithm => {
                write!(f, "unsupported algorithm")
            },
        }
    }
}
