//! Public key types for the RPO Falcon 512 digital signature scheme used in Miden VM.

use alloc::{string::ToString, vec::Vec};

use fn_dsa_vrfy::{VerifyingKey, VerifyingKey512};

use super::{
    super::{
        LOG_N, N, PK_LEN,
        math::{FalconFelt, Polynomial},
    },
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, Signature,
};
use crate::{SequentialCommit, Word};

// PUBLIC KEY
// ================================================================================================

/// Public key for Falcon-512 DSA.
///
/// Internally stores the encoded public key bytes in fn-dsa format. The bytes can be
/// decoded to a `VerifyingKey512` on demand for verification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    encoded: [u8; PK_LEN],
}

impl PublicKey {
    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, self)
    }

    /// Recovers from the signature the public key associated to the secret key used to sign
    /// a message.
    pub fn recover_from(_message: Word, signature: &Signature) -> Self {
        signature.public_key().clone()
    }

    /// Returns a commitment to the public key using the RPO256 hash function.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the encoded public key bytes.
    pub fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.encoded
    }

    /// Returns the public key as a polynomial over the Falcon prime field.
    pub fn to_polynomial(&self) -> Polynomial<FalconFelt> {
        let h = self.decode_coefficients();
        let coefficients: Vec<FalconFelt> = h.iter().map(|&v| FalconFelt::new(v)).collect();
        Polynomial::new(coefficients)
    }

    /// Decodes the stored bytes into a VerifyingKey512 for verification operations.
    pub(crate) fn decode_verifying_key(&self) -> Option<VerifyingKey512> {
        VerifyingKey512::decode(&self.encoded)
    }

    /// Decodes the public key polynomial coefficients from the stored bytes.
    fn decode_coefficients(&self) -> [u16; N] {
        let mut h = [0u16; N];
        // Skip the header byte (LOG_N)
        fn_dsa_comm::codec::modq_decode(&self.encoded[1..], &mut h)
            .expect("encoded key should be valid");
        h
    }
}

impl SequentialCommit for PublicKey {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let h = self.decode_coefficients();
        h.iter().map(|&v| Felt::new(v as u64)).collect()
    }
}

impl Serializable for &PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.encoded);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let encoded: [u8; PK_LEN] = source.read_array()?;

        if encoded[0] != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected the first byte to be {LOG_N} but was {}",
                encoded[0]
            )));
        }

        // Validate by attempting to decode
        VerifyingKey512::decode(&encoded).ok_or_else(|| {
            DeserializationError::InvalidValue(
                "Failed to decode public key: invalid encoding".to_string(),
            )
        })?;

        Ok(Self { encoded })
    }
}
