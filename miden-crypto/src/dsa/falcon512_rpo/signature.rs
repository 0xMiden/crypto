use alloc::{string::ToString, vec::Vec};
use core::ops::Deref;

use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, LOG_N, N, Nonce,
    SIG_POLY_BYTE_LEN, Serializable,
    hash_to_point::hash_to_point_rpo256,
    keys::PublicKey,
    math::{FalconFelt, Polynomial},
};
use crate::{Word, utils::zeroize::Zeroize};

// FALCON SIGNATURE
// ================================================================================================

/// A deterministic RPO Falcon512 signature over a message.
///
/// The signature is a pair of polynomials (s1, s2) in (Z_p\[x\]/(phi))^2, a nonce `r`, and a public
/// key polynomial `h` where:
/// - p := 12289
/// - phi := x^512 + 1
///
/// The signature verifies against a public key `pk` if and only if:
/// 1. s1 = c - s2 * h
/// 2. |s1|^2 + |s2|^2 <= β² (where β² = 34034726 for Falcon-512)
///
/// where |.| is the norm and:
/// - c = HashToPoint(r || message) using RPO256
/// - pk = Rpo256::hash(h)
///
/// Here h is a polynomial representing the public key and pk is its digest using the Rpo256 hash
/// function. c is a polynomial that is the hash-to-point of the message being signed.
///
/// ## Differences from Standard FN-DSA
///
/// 1. **Hash-to-point**: Uses RPO256 instead of SHAKE256 for efficient ZK verification.
/// 2. **Deterministic signing**: The PRNG seed is derived from BLAKE3(LOG_N || sk || message),
///    ensuring reproducible signatures. Following FN-DSA semantics, each signing attempt generates
///    a fresh nonce and recomputes hash-to-point.
///
/// ## Serialization Format
///
/// The signature is serialized as:
/// 1. Header byte (1 byte): Specifies encoding algorithm. Set to `0xB9` for RPO Falcon512.
/// 2. Nonce (40 bytes): The nonce used in hash-to-point.
/// 3. s2 polynomial (625 bytes): Compressed signature polynomial.
/// 4. Public key (897 bytes): 1 byte LOG_N + 896 bytes encoded h polynomial.
///
/// Total serialized size: 1563 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    header: SignatureHeader,
    nonce: Nonce,
    s2: SignaturePoly,
    h: PublicKey,
}

impl Signature {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new signature from the given nonce, public key polynomial, and signature
    /// polynomial.
    pub fn new(nonce: Nonce, h: PublicKey, s2: SignaturePoly) -> Signature {
        Self {
            header: SignatureHeader::default(),
            nonce,
            s2,
            h,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key polynomial h.
    pub fn public_key(&self) -> &PublicKey {
        &self.h
    }

    /// Returns the polynomial representation of the signature in Z_p\[x\]/(phi).
    pub fn sig_poly(&self) -> &Polynomial<FalconFelt> {
        &self.s2
    }

    /// Returns the nonce component of the signature.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Returns true if this signature is a valid signature for the specified message generated
    /// against the secret key matching the specified public key commitment.
    pub fn verify(&self, message: Word, pub_key: &PublicKey) -> bool {
        if self.h != *pub_key {
            return false;
        }
        let c = hash_to_point_rpo256(message, &self.nonce);
        verify_helper(&c, &self.s2, pub_key)
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.header);
        target.write(&self.nonce);
        target.write(&self.s2);
        target.write(&self.h);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read()?;
        let nonce = source.read()?;
        let s2 = source.read()?;
        let h = source.read()?;

        Ok(Self { header, nonce, s2, h })
    }
}

// SIGNATURE HEADER
// ================================================================================================

/// The header byte used to encode the signature metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader(u8);

impl Default for SignatureHeader {
    /// According to section 3.11.3 in the specification [1],  the signature header has the format
    /// `0cc1nnnn` where:
    ///
    /// 1. `cc` signifies the encoding method. `01` denotes using the compression encoding method
    ///    and `10` denotes encoding using the uncompressed method.
    /// 2. `nnnn` encodes `LOG_N`.
    ///
    /// For RPO Falcon 512 we use compression encoding and N = 512. Moreover, to differentiate the
    /// RPO Falcon variant from the reference variant using SHAKE256, we flip the first bit in the
    /// header. Thus, for RPO Falcon 512 the header is `10111001`
    ///
    /// [1]: https://falcon-sign.info/falcon.pdf
    fn default() -> Self {
        Self(0b1011_1001)
    }
}

impl Serializable for &SignatureHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0)
    }
}

impl Deserializable for SignatureHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read_u8()?;
        let (encoding, log_n) = (header >> 4, header & 0b00001111);
        if encoding != 0b1011 {
            return Err(DeserializationError::InvalidValue(
                "Failed to decode signature: not supported encoding algorithm".to_string(),
            ));
        }

        if log_n != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode signature: only supported irreducible polynomial degree is 512, 2^{log_n} was provided"
            )));
        }

        Ok(Self(header))
    }
}

// SIGNATURE POLYNOMIAL
// ================================================================================================

/// A polynomial used as the `s2` component of the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePoly(pub Polynomial<FalconFelt>);

impl Deref for SignaturePoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for SignaturePoly {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl TryFrom<&[i16; N]> for SignaturePoly {
    type Error = ();

    fn try_from(coefficients: &[i16; N]) -> Result<Self, Self::Error> {
        if are_coefficients_valid(coefficients) {
            Ok(Self(coefficients.to_vec().into()))
        } else {
            Err(())
        }
    }
}

impl Serializable for &SignaturePoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut sig_coeff: Vec<i16> =
            self.0.coefficients.iter().map(|a| a.balanced_value()).collect();
        let mut sk_bytes = vec![0_u8; SIG_POLY_BYTE_LEN];

        // Use fn-dsa-comm's compressed encoding
        // This should never fail for valid SignaturePoly instances since they are
        // constructed via TryFrom which validates coefficient bounds
        encode_signature_poly(&sig_coeff, &mut sk_bytes).then_some(()).expect(
            "signature polynomial encoding should never fail for valid coefficients; \
             this indicates a programming error in SignaturePoly validation",
        );

        target.write_bytes(&sk_bytes);

        // Zeroize temporary buffers
        sig_coeff.zeroize();
        sk_bytes.zeroize();
    }
}

impl Deserializable for SignaturePoly {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let input = source.read_array::<SIG_POLY_BYTE_LEN>()?;

        // Use fn-dsa-comm's compressed decoding
        let coefficients = decode_signature_poly(&input)?;

        Ok(Polynomial::new(coefficients.to_vec()).into())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Encodes signature polynomial coefficients using fn-dsa-comm's compressed encoding.
fn encode_signature_poly(sig_coeff: &[i16], output: &mut [u8]) -> bool {
    fn_dsa_comm::codec::comp_encode(sig_coeff, output)
}

/// Decodes signature polynomial coefficients using fn-dsa-comm's compressed encoding.
fn decode_signature_poly(input: &[u8]) -> Result<[FalconFelt; N], DeserializationError> {
    let mut coefficients_i16 = [0i16; N];

    if !fn_dsa_comm::codec::comp_decode(input, &mut coefficients_i16) {
        return Err(DeserializationError::InvalidValue(
            "Failed to decode signature polynomial".to_string(),
        ));
    }

    let coefficients = core::array::from_fn(|i| FalconFelt::from(coefficients_i16[i]));

    Ok(coefficients)
}

/// Takes the hash-to-point polynomial `c` of a message, the signature polynomial over
/// the message `s2` and a public key polynomial and returns `true` if the signature is valid,
/// otherwise it returns `false`.
fn verify_helper(c: &Polynomial<FalconFelt>, s2: &SignaturePoly, h: &PublicKey) -> bool {
    use fn_dsa_vrfy::VerifyingKey;

    // Decode the public key into fn-dsa's VerifyingKey512.
    let vk = match h.decode_verifying_key() {
        Some(vk) => vk,
        None => return false,
    };

    // Convert c to external representation [0, q-1]
    let hm: [u16; N] = core::array::from_fn(|i| c.coefficients[i].value());

    // Convert s2 to signed coefficients
    let s2_signed = s2.to_i16_balanced_array();

    // Use fn-dsa's verify_prehash
    vk.verify_prehash(&hm, &s2_signed)
}

/// Checks whether a set of coefficients is a valid one for a signature polynomial.
fn are_coefficients_valid(x: &[i16]) -> bool {
    if x.len() != N {
        return false;
    }

    for &c in x {
        if !(-2047..=2047).contains(&c) {
            return false;
        }
    }

    true
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{
        super::{SIG_SERIALIZED_LEN, SecretKey},
        *,
    };

    #[test]
    fn test_serialization_round_trip() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        let sk = SecretKey::with_rng(&mut rng);
        let signature = sk.sign_with_rng(Word::default(), &mut rng);
        let serialized = signature.to_bytes();
        assert_eq!(serialized.len(), SIG_SERIALIZED_LEN);
        let deserialized = Signature::read_from_bytes(&serialized).unwrap();
        assert_eq!(signature.sig_poly(), deserialized.sig_poly());
    }
}
