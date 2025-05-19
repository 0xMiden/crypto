//! Public key types for the RPO Falcon 512 digital signature scheme used in Miden VM.
//!
//! This module defines two main types:
//! - `PublicKey`: A commitment to a polynomial, represented as a hash of the polynomial’s
//!   coefficients.
//! - `PubKeyPoly`: A public key represented directly as a polynomial over FalconFelt coefficients.
//!
//! The `PublicKey` is used for signature verification.
//! The `PubKeyPoly` provides the raw polynomial form of a public key.

use alloc::string::ToString;
use core::ops::Deref;

use num::Zero;

use super::{
    super::{LOG_N, N, PK_LEN, Rpo256},
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconFelt, Felt, Polynomial,
    Serializable, Signature,
};
use crate::{Word, dsa::rpo_falcon512::FALCON_ENCODING_BITS};

// PUBLIC KEY
// ================================================================================================

/// A public key for verifying signatures.
///
/// The public key is a [Word] (i.e., 4 field elements) that is the hash of the coefficients of
/// the polynomial representing the raw bytes of the expanded public key. The hash is computed
/// using Rpo256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(Word);

impl PublicKey {
    /// Returns a new [PublicKey] which is a commitment to the provided expanded public key.
    pub fn new(pub_key: Word) -> Self {
        Self(pub_key)
    }

    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, self.0)
    }
}

impl From<PubKeyPoly> for PublicKey {
    fn from(pk_poly: PubKeyPoly) -> Self {
        let pk_felts: Polynomial<Felt> = pk_poly.0.into();
        let pk_digest = Rpo256::hash_elements(&pk_felts.coefficients);
        Self(pk_digest)
    }
}

impl From<PublicKey> for Word {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

// PUBLIC KEY POLYNOMIAL
// ================================================================================================

/// Public key represented as a polynomial with coefficients over the Falcon prime field.
/// Used in the RPO Falcon 512 signature scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKeyPoly(pub Polynomial<FalconFelt>);

impl Deref for PubKeyPoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for PubKeyPoly {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl Serializable for &PubKeyPoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut buf = [0_u8; PK_LEN];
        buf[0] = LOG_N;

        let mut acc = 0_u32;
        let mut acc_len: u32 = 0;

        let mut input_pos = 1;
        for c in self.0.coefficients.iter() {
            let c = c.value();
            acc = (acc << FALCON_ENCODING_BITS) | c as u32;
            acc_len += FALCON_ENCODING_BITS;
            while acc_len >= 8 {
                acc_len -= 8;
                buf[input_pos] = (acc >> acc_len) as u8;
                input_pos += 1;
            }
        }
        if acc_len > 0 {
            buf[input_pos] = (acc >> (8 - acc_len)) as u8;
        }

        target.write(buf);
    }
}

impl Deserializable for PubKeyPoly {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let buf = source.read_array::<PK_LEN>()?;

        if buf[0] != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected the first byte to be {LOG_N} but was {}",
                buf[0]
            )));
        }

        let mut acc = 0_u32;
        let mut acc_len = 0;

        let mut output = [FalconFelt::zero(); N];
        let mut output_idx = 0;

        for &byte in buf.iter().skip(1) {
            acc = (acc << 8) | (byte as u32);
            acc_len += 8;

            if acc_len >= FALCON_ENCODING_BITS {
                acc_len -= FALCON_ENCODING_BITS;
                let w = (acc >> acc_len) & 0x3fff;
                let element = w.try_into().map_err(|err| {
                    DeserializationError::InvalidValue(format!(
                        "Failed to decode public key: {err}"
                    ))
                })?;
                output[output_idx] = element;
                output_idx += 1;
            }
        }

        if (acc & ((1u32 << acc_len) - 1)) == 0 {
            Ok(Polynomial::new(output.to_vec()).into())
        } else {
            Err(DeserializationError::InvalidValue(
                "Failed to decode public key: input not fully consumed".to_string(),
            ))
        }
    }
}
