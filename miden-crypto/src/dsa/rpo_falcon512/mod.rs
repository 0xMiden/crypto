#[cfg(test)]
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

/// Length of nonce used for signature generation.
const SIG_NONCE_LEN: usize = 40;

/// Length of the preversioned portion of the fixed nonce.
///
/// Since we use one byte to encode the version of the nonce, this is equal to `SIG_NONCE_LEN - 1`.
const PREVERSIONED_NONCE_LEN: usize = 39;

/// Current version of the fixed nonce.
///
/// The usefulness of the notion of versioned fixed nonce is discussed in Section 2.1 in [1].
///
/// [1]: https://github.com/algorand/falcon/blob/main/falcon-det.pdf
const NONCE_VERSION_BYTE: u8 = 1;

/// The preversioned portion of the fixed nonce constructed following [1].
///
/// Note that reference [1] uses the term salt instead of nonce.
const PREVERSIONED_NONCE: [u8; PREVERSIONED_NONCE_LEN] = [
    9, 82, 80, 79, 45, 70, 65, 76, 67, 79, 78, 45, 68, 69, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

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
pub struct Nonce {
    nonce_version: u8,
    preversioned_nonce: [u8; PREVERSIONED_NONCE_LEN],
}

impl Nonce {
    /// Returns a new [Nonce].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            nonce_version: NONCE_VERSION_BYTE,
            preversioned_nonce: PREVERSIONED_NONCE,
        }
    }

    /// Returns a new [Nonce] drawn from the provided RNG.
    ///
    /// This is used only in testing against the test vectors of the reference (non-deterministic)
    /// Falcon DSA implementation.
    #[cfg(test)]
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        Self::from_bytes(nonce_bytes)
    }

    /// Returns the underlying concatenated bytes of this nonce.
    pub fn as_bytes(&self) -> [u8; SIG_NONCE_LEN] {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        nonce_bytes[0] = self.nonce_version;
        nonce_bytes
            .iter_mut()
            .skip(1)
            .zip(self.preversioned_nonce.iter())
            .for_each(|(dst, src)| *dst = *src);

        nonce_bytes
    }

    /// Returns a `Nonce` given an array of bytes.
    pub fn from_bytes(nonce_bytes: [u8; SIG_NONCE_LEN]) -> Self {
        let nonce_version = nonce_bytes[0];
        let preversioned_nonce = (&nonce_bytes[1..]).try_into().expect("should not fail");
        Self { nonce_version, preversioned_nonce }
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
        target.write_u8(self.nonce_version)
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nonce_version = source.read()?;
        Ok(Self {
            nonce_version,
            preversioned_nonce: PREVERSIONED_NONCE,
        })
    }
}
