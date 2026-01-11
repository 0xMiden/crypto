//! Public key types for the RPO Falcon 512 digital signature scheme used in Miden VM.

use alloc::{string::ToString, vec::Vec};
use core::ops::Deref;

use super::{
    super::{LOG_N, N, PK_LEN},
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconFelt, Felt, Polynomial,
    Serializable, Signature,
};
use crate::{SequentialCommit, Word};

// PUBLIC KEY
// ================================================================================================

/// Public key represented as a polynomial with coefficients over the Falcon prime field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Polynomial<FalconFelt>);

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
}

impl SequentialCommit for PublicKey {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        Into::<Polynomial<Felt>>::into(self.0.clone()).coefficients
    }
}

impl Deref for PublicKey {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for PublicKey {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl Serializable for &PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut buf = [0_u8; PK_LEN];
        buf[0] = LOG_N;

        // Convert FalconFelt coefficients to u16 external representation [0, q-1]
        let h: Vec<u16> = self.0.coefficients.iter().map(|c| c.value()).collect();

        // Use fn-dsa-comm's modq_encode to encode 512 coefficients at 14 bits each
        // This encodes 4 coefficients per 7 bytes (512/4 = 128 groups = 896 bytes)
        let written = fn_dsa_comm::codec::modq_encode(&h, &mut buf[1..]);
        assert_eq!(written, PK_LEN - 1, "modq_encode should write exactly {} bytes", PK_LEN - 1);

        target.write(buf);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let buf = source.read_array::<PK_LEN>()?;

        if buf[0] != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected the first byte to be {LOG_N} but was {}",
                buf[0]
            )));
        }

        // Use fn-dsa-comm's modq_decode to decode 512 coefficients
        let mut h = [0u16; N];
        let read_bytes = fn_dsa_comm::codec::modq_decode(&buf[1..], &mut h).ok_or_else(|| {
            DeserializationError::InvalidValue(
                "Failed to decode public key: invalid modq encoding".to_string(),
            )
        })?;

        // Verify we consumed exactly the expected number of bytes
        if read_bytes != PK_LEN - 1 {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected {} bytes, read {}",
                PK_LEN - 1,
                read_bytes
            )));
        }

        // Convert u16 values to FalconFelt (modq_decode already validates values are in [0, q-1])
        let coefficients: Vec<FalconFelt> = h.iter().map(|&v| FalconFelt::new(v)).collect();

        Ok(Polynomial::new(coefficients).into())
    }
}
