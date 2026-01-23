//! Deterministic RPO Falcon512 signature scheme.
//!
//! This implementation differs from standard FN-DSA (FIPS 206) in its use of RPO256 for
//! the hash-to-point algorithm instead of SHAKE256. This enables efficient verification
//! inside Miden's VM.
//!
//! ## Deterministic Signing
//!
//! The signing process is deterministic: the same (secret_key, message) pair always produces
//! the same signature. This is achieved by deriving the PRNG seed from the secret key and
//! message using BLAKE3.
//!
//! Following FN-DSA semantics, each signing attempt generates a fresh nonce and recomputes
//! hash-to-point. The deterministic seed controls both the nonce generation and signature
//! sampling PRNGs, ensuring reproducibility across retries.

use fn_dsa_comm::{FN_DSA_LOGN_512, sign_key_size, vrfy_key_size};

use crate::{
    Felt, ZERO,
    hash::rpo::Rpo256,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod hash_to_point;
mod keys;
mod math;
mod signature;

#[cfg(test)]
mod tests;

pub use self::{
    keys::{PublicKey, SecretKey},
    math::Polynomial,
    signature::{Signature, SignatureHeader, SignaturePoly},
};

// CONSTANTS
// ================================================================================================

// The Falcon modulus p.
const MODULUS: i16 = 12289;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring Z_p[x]/(phi).
const N: usize = 512;
const LOG_N: u8 = 9;

/// Length of nonce used for signature generation.
const SIG_NONCE_LEN: usize = 40;

/// Number of field elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
pub const PK_LEN: usize = vrfy_key_size(FN_DSA_LOGN_512);

/// Secret key length as a u8 vector.
pub const SK_LEN: usize = sign_key_size(FN_DSA_LOGN_512);

/// Signature length as a u8 vector.
const SIG_POLY_BYTE_LEN: usize = 625;

/// Signature size when serialized as a u8 vector.
/// 1 (header) + 40 (nonce) + 625 (s2 poly) + 897 (public key) = 1563
#[cfg(test)]
const SIG_SERIALIZED_LEN: usize = 1563;

// NONCE
// ================================================================================================

/// Nonce of the Falcon signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; SIG_NONCE_LEN]);

impl Nonce {
    /// Returns the underlying concatenated bytes of this nonce.
    pub fn as_bytes(&self) -> [u8; SIG_NONCE_LEN] {
        self.0
    }

    /// Returns a `Nonce` given an array of bytes.
    pub fn from_bytes(nonce_bytes: [u8; SIG_NONCE_LEN]) -> Self {
        Self(nonce_bytes)
    }

    /// Converts byte representation of the nonce into field element representation.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5 byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; 8];
        for (i, bytes) in self.as_bytes().chunks(5).enumerate() {
            buffer[..5].copy_from_slice(bytes);
            // we can safely (without overflow) create a new Felt from u64 value here since this
            // value contains at most 5 bytes
            result[i] = Felt::new(u64::from_le_bytes(buffer));
        }

        result
    }
}

impl Serializable for &Nonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nonce_bytes: [u8; SIG_NONCE_LEN] = source.read_array()?;
        Ok(Self(nonce_bytes))
    }
}
