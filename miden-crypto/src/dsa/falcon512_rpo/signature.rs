use alloc::{string::ToString, vec::Vec};
use core::ops::Deref;

use num::Zero;

use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, LOG_N, N, Nonce, SIG_L2_BOUND,
    SIG_POLY_BYTE_LEN, Serializable,
    hash_to_point::hash_to_point_rpo256,
    keys::PublicKey,
    math::{FalconFelt, FastFft, Polynomial},
};
use crate::{Word, utils::zeroize::Zeroize};

// FALCON SIGNATURE
// ================================================================================================

/// A deterministic RPO Falcon512 signature over a message.
///
/// The signature is a pair of polynomials (s1, s2) in (Z_p\[x\]/(phi))^2 a nonce `r`, and a public
/// key polynomial `h` where:
/// - p := 12289
/// - phi := x^512 + 1
///
/// The signature  verifies against a public key `pk` if and only if:
/// 1. s1 = c - s2 * h
/// 2. |s1|^2 + |s2|^2 <= SIG_L2_BOUND
///
/// where |.| is the norm and:
/// - c = HashToPoint(r || message)
/// - pk = Rpo256::hash(h)
///
/// Here h is a polynomial representing the public key and pk is its digest using the Rpo256 hash
/// function. c is a polynomial that is the hash-to-point of the message being signed.
///  
///  To summarize the main points of differences with the reference implementation, we have that:
///
/// 1. the hash-to-point algorithm is made deterministic by using a fixed nonce `r`. This fixed
///    nonce is formed as `nonce_version_byte || preversioned_nonce` where `preversioned_nonce` is a
///    39-byte string that is defined as: i. a byte representing `log_2(512)`, followed by ii. the
///    UTF8 representation of the string "RPO-FALCON-DET", followed by iii. the required number of
///    0_u8 padding to make the total length equal 39 bytes. Note that the above means in particular
///    that only the `nonce_version_byte` needs to be serialized when serializing the signature.
///    This reduces the deterministic signature compared to the reference implementation by 39
///    bytes.
/// 2. the RNG used in the trapdoor sampler (i.e., the ffSampling algorithm) is ChaCha20Rng seeded
///    with the `Blake3` hash of `log_2(512) || sk || message`.
///
/// The signature is serialized as:
///
/// 1. A header byte specifying the algorithm used to encode the coefficients of the `s2` polynomial
///    together with the degree of the irreducible polynomial phi. For RPO Falcon512, the header
///    byte is set to `10111001` to differentiate it from the standardized instantiation of the
///    Falcon signature.
/// 2. 1 byte for the nonce version.
/// 4. 625 bytes encoding the `s2` polynomial above.
///
/// In addition to the signature itself, the polynomial h is also serialized with the signature as:
///
/// 1. 1 byte representing the log2(512) i.e., 9.
/// 2. 896 bytes for the public key itself.
///
/// The total size of the signature (including the extended public key) is 1524 bytes.
///
/// [1]: https://github.com/algorand/falcon/blob/main/falcon-det.pdf
/// [2]: https://datatracker.ietf.org/doc/html/rfc6979#section-3.5
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

    let mut coefficients = [FalconFelt::zero(); N];
    for (i, &coeff) in coefficients_i16.iter().enumerate() {
        coefficients[i] = FalconFelt::from(coeff);
    }

    Ok(coefficients)
}

/// Takes the hash-to-point polynomial `c` of a message, the signature polynomial over
/// the message `s2` and a public key polynomial and returns `true` is the signature is a valid
/// signature for the given parameters, otherwise it returns `false`.
fn verify_helper(c: &Polynomial<FalconFelt>, s2: &SignaturePoly, h: &PublicKey) -> bool {
    let h_fft = h.fft();
    let s2_fft = s2.fft();
    let c_fft = c.fft();

    // compute the signature polynomial s1 using s1 = c - s2 * h
    let s1_fft = c_fft - s2_fft.hadamard_mul(&h_fft);
    let s1 = s1_fft.ifft();

    // compute the norm squared of (s1, s2)
    let length_squared_s1 = s1.norm_squared();
    let length_squared_s2 = s2.norm_squared();
    let length_squared = length_squared_s1 + length_squared_s2;

    length_squared < SIG_L2_BOUND
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
