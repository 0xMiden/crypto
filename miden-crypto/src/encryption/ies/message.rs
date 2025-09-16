use alloc::vec::Vec;

use super::error::IntegratedEncryptionSchemeError;
use super::keys::EphemeralPublicKey;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use core::convert::TryFrom;

/// Supported algorithms for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CryptoAlgorithm {
    K256XChaCha20Poly1305 = 0,
}

impl TryFrom<u8> for CryptoAlgorithm {
    type Error = IntegratedEncryptionSchemeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CryptoAlgorithm::K256XChaCha20Poly1305),
            _ => Err(IntegratedEncryptionSchemeError::UnsupportedAlgorithm),
        }
    }
}

impl From<CryptoAlgorithm> for u8 {
    fn from(algo: CryptoAlgorithm) -> Self {
        algo as u8
    }
}

impl core::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl CryptoAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            CryptoAlgorithm::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
        }
    }
}

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Ephemeral public key (determines algorithm and provides key material)
    pub(crate) ephemeral_key: EphemeralPublicKey,
    /// Encrypted ciphertext with authentication tag
    pub(crate) ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub(crate) nonce: Vec<u8>,
}

impl SealedMessage {
    /// Get the algorithm used to create this sealed message
    pub(crate) fn algorithm(&self) -> CryptoAlgorithm {
        self.ephemeral_key.algorithm()
    }

    /// Get the algorithm name used to create this sealed message
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let algorithm = self.algorithm();
        target.write_u8(algorithm as u8);

        let eph_key_bytes = self.ephemeral_key.to_bytes();
        target.write_usize(eph_key_bytes.len());
        target.write_bytes(&eph_key_bytes);

        target.write_usize(self.ciphertext.len());
        target.write_bytes(&self.ciphertext);

        target.write_usize(self.nonce.len());
        target.write_bytes(&self.nonce);
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let algorithm = match CryptoAlgorithm::try_from(source.read_u8()?) {
            Ok(a) => a,
            Err(_) => {
                return Err(DeserializationError::InvalidValue("Unsupported algorithm".into()));
            },
        };

        let eph_key_len = source.read_usize()?;
        let eph_key_bytes = source.read_vec(eph_key_len)?;
        let ephemeral_key =
            EphemeralPublicKey::from_bytes(algorithm, &eph_key_bytes).map_err(|e| {
                DeserializationError::InvalidValue(format!("Invalid ephemeral key: {e}"))
            })?;

        let ciphertext_len = source.read_usize()?;
        let ciphertext = source.read_vec(ciphertext_len)?;

        let nonce_len = source.read_usize()?;
        let nonce = source.read_vec(nonce_len)?;

        Ok(Self { ephemeral_key, ciphertext, nonce })
    }
}
