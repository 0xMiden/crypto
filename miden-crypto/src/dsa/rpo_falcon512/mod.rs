use rand::Rng;

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
    keys::{PubKeyPoly, PublicKey, SecretKey},
    math::Polynomial,
    signature::{Signature, SignatureHeader, SignaturePoly},
};

// CONSTANTS
// ================================================================================================

// The Falcon modulus p.
const MODULUS: i16 = 12289;

// Number of bits needed to encode an element in the Falcon field.
const FALCON_ENCODING_BITS: u32 = 14;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring Z_p[x]/(phi).
const N: usize = 512;
const LOG_N: u8 = 9;

/// Length of nonce used for key-pair generation.
const SIG_NONCE_LEN: usize = 40;

/// Number of filed elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
pub const PK_LEN: usize = 897;

/// Secret key length as a u8 vector.
pub const SK_LEN: usize = 1281;

/// Signature length as a u8 vector.
const SIG_POLY_BYTE_LEN: usize = 625;

/// Bound on the squared-norm of the signature.
const SIG_L2_BOUND: u64 = 34034726;

/// Standard deviation of the Gaussian over the lattice.
const SIGMA: f64 = 165.7366171829776;

// TYPE ALIASES
// ================================================================================================

type ShortLatticeBasis = [Polynomial<i16>; 4];

// NONCE
// ================================================================================================

/// Nonce of the Falcon signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; SIG_NONCE_LEN]);

impl Nonce {
    /// Returns a new [Nonce] instantiated from the provided bytes.
    pub fn new(bytes: [u8; SIG_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a new [Nonce] drawn from the provided RNG.
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        Self::new(nonce_bytes)
    }

    /// Returns the underlying bytes of this nonce.
    pub fn as_bytes(&self) -> &[u8; SIG_NONCE_LEN] {
        &self.0
    }

    /// Converts byte representation of the nonce into field element representation.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5 byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; 8];
        for (i, bytes) in self.0.chunks(5).enumerate() {
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
        target.write_bytes(&self.0)
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = source.read()?;
        Ok(Self(bytes))
    }
}
