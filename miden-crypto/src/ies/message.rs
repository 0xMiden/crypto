use alloc::vec::Vec;
use core::convert::TryFrom;

use super::{error::IntegratedEncryptionSchemeError, keys::EphemeralPublicKey};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Supported algorithms for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum IesAlgorithm {
    K256XChaCha20Poly1305 = 0,
    X25519XChaCha20Poly1305 = 1,
    X25519AeadRpo = 2,
}

impl TryFrom<u8> for IesAlgorithm {
    type Error = IntegratedEncryptionSchemeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IesAlgorithm::K256XChaCha20Poly1305),
            1 => Ok(IesAlgorithm::X25519XChaCha20Poly1305),
            2 => Ok(IesAlgorithm::X25519AeadRpo),
            _ => Err(IntegratedEncryptionSchemeError::UnsupportedAlgorithm),
        }
    }
}

impl From<IesAlgorithm> for u8 {
    fn from(algo: IesAlgorithm) -> Self {
        algo as u8
    }
}

impl core::fmt::Display for IesAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl IesAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            IesAlgorithm::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
            IesAlgorithm::X25519XChaCha20Poly1305 => "X25519+XChaCha20-Poly1305",
            IesAlgorithm::X25519AeadRpo => "X25519+AeadRpo",
        }
    }
}

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Ephemeral public key (determines algorithm and provides key material)
    pub(crate) ephemeral_key: EphemeralPublicKey,
    /// Encrypted ciphertext with authentication tag and nonce
    pub(crate) ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Get the algorithm used to create this sealed message
    pub(crate) fn algorithm(&self) -> IesAlgorithm {
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
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let algorithm = match IesAlgorithm::try_from(source.read_u8()?) {
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

        Ok(Self { ephemeral_key, ciphertext })
    }
}
