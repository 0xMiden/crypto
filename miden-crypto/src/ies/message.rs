use alloc::vec::Vec;
use core::convert::TryFrom;

use super::{error::IesError, keys::EphemeralPublicKey};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Supported schemes for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum IesScheme {
    K256XChaCha20Poly1305 = 0,
    X25519XChaCha20Poly1305 = 1,
    K256AeadRpo = 2,
    X25519AeadRpo = 3,
}

impl TryFrom<u8> for IesScheme {
    type Error = IesError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IesScheme::K256XChaCha20Poly1305),
            1 => Ok(IesScheme::X25519XChaCha20Poly1305),
            2 => Ok(IesScheme::K256AeadRpo),
            3 => Ok(IesScheme::X25519AeadRpo),
            _ => Err(IesError::UnsupportedScheme),
        }
    }
}

impl From<IesScheme> for u8 {
    fn from(algo: IesScheme) -> Self {
        algo as u8
    }
}

impl core::fmt::Display for IesScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl IesScheme {
    pub fn name(self) -> &'static str {
        match self {
            IesScheme::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
            IesScheme::X25519XChaCha20Poly1305 => "X25519+XChaCha20-Poly1305",
            IesScheme::K256AeadRpo => "K256+AeadRpo",
            IesScheme::X25519AeadRpo => "X25519+AeadRpo",
        }
    }
}

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Ephemeral public key (determines scheme and provides key material)
    pub(crate) ephemeral_key: EphemeralPublicKey,
    /// Encrypted ciphertext with authentication tag and nonce
    pub(crate) ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Get the scheme used to create this sealed message
    pub(crate) fn scheme(&self) -> IesScheme {
        self.ephemeral_key.scheme()
    }

    /// Get the scheme name used to create this sealed message
    pub fn scheme_name(&self) -> &'static str {
        self.scheme().name()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let scheme = self.scheme();
        target.write_u8(scheme as u8);

        let eph_key_bytes = self.ephemeral_key.to_bytes();
        target.write_usize(eph_key_bytes.len());
        target.write_bytes(&eph_key_bytes);

        target.write_usize(self.ciphertext.len());
        target.write_bytes(&self.ciphertext);
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = match IesScheme::try_from(source.read_u8()?) {
            Ok(a) => a,
            Err(_) => {
                return Err(DeserializationError::InvalidValue("Unsupported scheme".into()));
            },
        };

        let eph_key_len = source.read_usize()?;
        let eph_key_bytes = source.read_vec(eph_key_len)?;
        let ephemeral_key =
            EphemeralPublicKey::from_bytes(scheme, &eph_key_bytes).map_err(|e| {
                DeserializationError::InvalidValue(format!("Invalid ephemeral key: {e}"))
            })?;

        let ciphertext_len = source.read_usize()?;
        let ciphertext = source.read_vec(ciphertext_len)?;

        Ok(Self { ephemeral_key, ciphertext })
    }
}
