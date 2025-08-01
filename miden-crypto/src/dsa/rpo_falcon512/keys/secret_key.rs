use alloc::{string::ToString, vec::Vec};

use num::Complex;
#[cfg(not(feature = "std"))]
use num::Float;
use num_complex::Complex64;
use rand::Rng;

use super::{
    super::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, MODULUS, N, Nonce,
        SIG_L2_BOUND, SIGMA, Serializable, ShortLatticeBasis, Signature,
        math::{FalconFelt, FastFft, LdlTree, Polynomial, ffldl, ffsampling, gram, normalize_tree},
        signature::SignaturePoly,
    },
    PublicKey,
};
use crate::{
    Word,
    dsa::rpo_falcon512::{LOG_N, SK_LEN, hash_to_point::hash_to_point_rpo256, math::ntru_gen},
    hash::blake::Blake3_256,
};

// CONSTANTS
// ================================================================================================

pub(crate) const WIDTH_BIG_POLY_COEFFICIENT: usize = 8;
pub(crate) const WIDTH_SMALL_POLY_COEFFICIENT: usize = 6;

// SECRET KEY
// ================================================================================================

/// Represents the secret key for Falcon DSA.
///
/// The secret key is a quadruple [[g, -f], [G, -F]] of polynomials with integer coefficients. Each
/// polynomial is of degree at most N = 512 and computations with these polynomials is done modulo
/// the monic irreducible polynomial ϕ = x^N + 1. The secret key is a basis for a lattice and has
/// the property of being short with respect to a certain norm and an upper bound appropriate for
/// a given security parameter. The public key on the other hand is another basis for the same
/// lattice and can be described by a single polynomial h with integer coefficients modulo ϕ.
/// The two keys are related by the following relation:
///
/// 1. h = g /f [mod ϕ][mod p]
/// 2. f.G - g.F = p [mod ϕ]
///
/// where p = 12289 is the Falcon prime. Equation 2 is called the NTRU equation.
/// The secret key is generated by first sampling a random pair (f, g) of polynomials using
/// an appropriate distribution that yields short but not too short polynomials with integer
/// coefficients modulo ϕ. The NTRU equation is then used to find a matching pair (F, G).
/// The public key is then derived from the secret key using equation 1.
///
/// To allow for fast signature generation, the secret key is pre-processed into a more suitable
/// form, called the LDL tree, and this allows for fast sampling of short vectors in the lattice
/// using Fast Fourier sampling during signature generation (ffSampling algorithm 11 in [1]).
///
/// [1]: https://falcon-sign.info/falcon.pdf
#[derive(Debug, Clone)]
pub struct SecretKey {
    secret_key: ShortLatticeBasis,
    tree: LdlTree,
}

#[allow(clippy::new_without_default)]
impl SecretKey {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Generates a secret key from OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::from_os_rng();
        Self::with_rng(&mut rng)
    }

    /// Generates a secret_key using the provided random number generator `Rng`.
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        let basis = ntru_gen(N, rng);
        Self::from_short_lattice_basis(basis)
    }

    /// Given a short basis [[g, -f], [G, -F]], computes the normalized LDL tree i.e., Falcon tree.
    pub(crate) fn from_short_lattice_basis(basis: ShortLatticeBasis) -> SecretKey {
        // FFT each polynomial of the short basis.
        let basis_fft = to_complex_fft(&basis);
        // compute the Gram matrix.
        let gram_fft = gram(basis_fft);
        // construct the LDL tree of the Gram matrix.
        let mut tree = ffldl(gram_fft);
        // normalize the leaves of the LDL tree.
        normalize_tree(&mut tree, SIGMA);
        Self { secret_key: basis, tree }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the polynomials of the short lattice basis of this secret key.
    pub fn short_lattice_basis(&self) -> &ShortLatticeBasis {
        &self.secret_key
    }

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> PublicKey {
        self.compute_pub_key_poly()
    }

    /// Returns the LDL tree associated to this secret key.
    pub fn tree(&self) -> &LdlTree {
        &self.tree
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with this secret key.
    pub fn sign(&self, message: crate::Word) -> Signature {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let seed = self.generate_seed(&message);
        let mut rng = ChaCha20Rng::from_seed(seed);
        self.sign_with_rng(message, &mut rng)
    }

    /// Signs a message with the secret key relying on the provided randomness generator.
    pub fn sign_with_rng<R: Rng>(&self, message: Word, rng: &mut R) -> Signature {
        let nonce = Nonce::deterministic();

        let h = self.compute_pub_key_poly();
        let c = hash_to_point_rpo256(message, &nonce);
        let s2 = self.sign_helper(c, rng);

        Signature::new(nonce, h, s2)
    }

    /// Signs a message with the secret key relying on the provided randomness generator.
    ///
    /// This is similar to [SecretKey::sign_with_rng()] and is used only for testing with
    /// the main difference being that this method:
    ///
    /// 1. uses `SHAKE256` for the hash-to-point algorithm, and
    /// 2. uses `ChaCha20` in `Self::sign_helper`.
    ///
    /// Hence, in contrast to `Self::sign_with_rng`, the current method uses different random
    /// number generators for generating the nonce and in `Self::sign_helper`.
    ///
    /// These changes make the signature algorithm compliant with the reference implementation.
    #[cfg(all(test, feature = "std"))]
    pub fn sign_with_rng_testing<R: Rng>(&self, message: &[u8], rng: &mut R) -> Signature {
        use crate::dsa::rpo_falcon512::{hash_to_point::hash_to_point_shake256, tests::ChaCha};

        let nonce = Nonce::random(rng);

        let h = self.compute_pub_key_poly();
        let c = hash_to_point_shake256(message, &nonce);

        let mut chacha_prng = ChaCha::new(rng);
        let s2 = self.sign_helper(c, &mut chacha_prng);

        Signature::new(nonce, h, s2)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Derives the public key corresponding to this secret key using h = g /f [mod ϕ][mod p].
    fn compute_pub_key_poly(&self) -> PublicKey {
        let g: Polynomial<FalconFelt> = self.secret_key[0].clone().into();
        let g_fft = g.fft();
        let minus_f: Polynomial<FalconFelt> = self.secret_key[1].clone().into();
        let f = -minus_f;
        let f_fft = f.fft();
        let h_fft = g_fft.hadamard_div(&f_fft);
        h_fft.ifft().into()
    }

    /// Signs a message polynomial with the secret key.
    ///
    /// Takes a randomness generator implementing `Rng` and message polynomial representing `c`
    /// the hash-to-point of the message to be signed. It outputs a signature polynomial `s2`.
    fn sign_helper<R: Rng>(&self, c: Polynomial<FalconFelt>, rng: &mut R) -> SignaturePoly {
        let one_over_q = 1.0 / (MODULUS as f64);
        let c_over_q_fft = c.map(|cc| Complex::new(one_over_q * cc.value() as f64, 0.0)).fft();

        // B = [[FFT(g), -FFT(f)], [FFT(G), -FFT(F)]]
        let [g_fft, minus_f_fft, big_g_fft, minus_big_f_fft] = to_complex_fft(&self.secret_key);
        let t0 = c_over_q_fft.hadamard_mul(&minus_big_f_fft);
        let t1 = -c_over_q_fft.hadamard_mul(&minus_f_fft);

        loop {
            let bold_s = loop {
                let z = ffsampling(&(t0.clone(), t1.clone()), &self.tree, rng);
                let t0_min_z0 = t0.clone() - z.0;
                let t1_min_z1 = t1.clone() - z.1;

                // s = (t-z) * B
                let s0 = t0_min_z0.hadamard_mul(&g_fft) + t1_min_z1.hadamard_mul(&big_g_fft);
                let s1 =
                    t0_min_z0.hadamard_mul(&minus_f_fft) + t1_min_z1.hadamard_mul(&minus_big_f_fft);

                // compute the norm of (s0||s1) and note that they are in FFT representation
                let length_squared: f64 =
                    (s0.coefficients.iter().map(|a| (a * a.conj()).re).sum::<f64>()
                        + s1.coefficients.iter().map(|a| (a * a.conj()).re).sum::<f64>())
                        / (N as f64);

                if length_squared > (SIG_L2_BOUND as f64) {
                    continue;
                }

                break [-s0, s1];
            };

            let s2 = bold_s[1].ifft();
            let s2_coef: [i16; N] = s2
                .coefficients
                .iter()
                .map(|a| a.re.round() as i16)
                .collect::<Vec<i16>>()
                .try_into()
                .expect("The number of coefficients should be equal to N");

            if let Ok(s2) = SignaturePoly::try_from(&s2_coef) {
                return s2;
            }
        }
    }

    /// Deterministically generates a seed for seeding the PRNG used in the trapdoor sampling
    /// algorithm used during signature generation.
    ///
    /// This uses the argument described in [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979#section-3.5)
    /// § 3.5 where the concatenation of the private key and the hashed message, i.e., sk || H(m),
    /// is used in order to construct the initial seed of a PRNG. See also [1].
    ///
    ///
    /// Note that we hash in also a `log_2(N)` where `N = 512` in order to domain separate between
    /// different versions of the Falcon DSA, see [1] Section 3.4.1.
    ///
    /// [1]: https://github.com/algorand/falcon/blob/main/falcon-det.pdf
    fn generate_seed(&self, message: &Word) -> [u8; 32] {
        let mut buffer = Vec::with_capacity(1 + SK_LEN + Word::SERIALIZED_SIZE);
        buffer.push(LOG_N);
        buffer.extend_from_slice(&self.to_bytes());
        buffer.extend_from_slice(&message.to_bytes());

        let digest = Blake3_256::hash(&buffer);

        digest.into()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let basis = &self.secret_key;

        // header
        let n = basis[0].coefficients.len();
        let l = n.checked_ilog2().unwrap() as u8;
        let header: u8 = (5 << 4) | l;

        let neg_f = &basis[1];
        let g = &basis[0];
        let neg_big_f = &basis[3];

        let mut buffer = Vec::with_capacity(1281);
        buffer.push(header);

        let f_i8: Vec<i8> = neg_f
            .coefficients
            .iter()
            .map(|&a| FalconFelt::new(-a).balanced_value() as i8)
            .collect();
        let f_i8_encoded = encode_i8(&f_i8, WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&f_i8_encoded);

        let g_i8: Vec<i8> = g
            .coefficients
            .iter()
            .map(|&a| FalconFelt::new(a).balanced_value() as i8)
            .collect();
        let g_i8_encoded = encode_i8(&g_i8, WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&g_i8_encoded);

        let big_f_i8: Vec<i8> = neg_big_f
            .coefficients
            .iter()
            .map(|&a| FalconFelt::new(-a).balanced_value() as i8)
            .collect();
        let big_f_i8_encoded = encode_i8(&big_f_i8, WIDTH_BIG_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&big_f_i8_encoded);
        target.write_bytes(&buffer);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let byte_vector: [u8; SK_LEN] = source.read_array()?;

        // check length
        if byte_vector.len() < 2 {
            return  Err(DeserializationError::InvalidValue("Invalid encoding length: Failed to decode as length is different from the one expected".to_string()));
        }

        // read fields
        let header = byte_vector[0];

        // check fixed bits in header
        if (header >> 4) != 5 {
            return Err(DeserializationError::InvalidValue("Invalid header format".to_string()));
        }

        // check log n
        let logn = (header & 15) as usize;
        let n = 1 << logn;

        // match against const variant generic parameter
        if n != N {
            return Err(DeserializationError::InvalidValue(
                "Unsupported Falcon DSA variant".to_string(),
            ));
        }

        if byte_vector.len() != SK_LEN {
            return Err(DeserializationError::InvalidValue("Invalid encoding length: Failed to decode as length is different from the one expected".to_string()));
        }

        let chunk_size_f = ((n * WIDTH_SMALL_POLY_COEFFICIENT) + 7) >> 3;
        let chunk_size_g = ((n * WIDTH_SMALL_POLY_COEFFICIENT) + 7) >> 3;
        let chunk_size_big_f = ((n * WIDTH_BIG_POLY_COEFFICIENT) + 7) >> 3;

        let f = decode_i8(&byte_vector[1..chunk_size_f + 1], WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        let g = decode_i8(
            &byte_vector[chunk_size_f + 1..(chunk_size_f + chunk_size_g + 1)],
            WIDTH_SMALL_POLY_COEFFICIENT,
        )
        .unwrap();
        let big_f = decode_i8(
            &byte_vector[(chunk_size_f + chunk_size_g + 1)
                ..(chunk_size_f + chunk_size_g + chunk_size_big_f + 1)],
            WIDTH_BIG_POLY_COEFFICIENT,
        )
        .unwrap();

        let f = Polynomial::new(f.iter().map(|&c| FalconFelt::new(c.into())).collect());
        let g = Polynomial::new(g.iter().map(|&c| FalconFelt::new(c.into())).collect());
        let big_f = Polynomial::new(big_f.iter().map(|&c| FalconFelt::new(c.into())).collect());

        // big_g * f - g * big_f = p (mod X^n + 1)
        let big_g = g.fft().hadamard_div(&f.fft()).hadamard_mul(&big_f.fft()).ifft();
        let basis = [
            g.map(|f| f.balanced_value()),
            -f.map(|f| f.balanced_value()),
            big_g.map(|f| f.balanced_value()),
            -big_f.map(|f| f.balanced_value()),
        ];
        Ok(Self::from_short_lattice_basis(basis))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the complex FFT of the secret key polynomials.
fn to_complex_fft(basis: &[Polynomial<i16>; 4]) -> [Polynomial<Complex<f64>>; 4] {
    let [g, f, big_g, big_f] = basis.clone();
    let g_fft = g.map(|cc| Complex64::new(*cc as f64, 0.0)).fft();
    let minus_f_fft = f.map(|cc| -Complex64::new(*cc as f64, 0.0)).fft();
    let big_g_fft = big_g.map(|cc| Complex64::new(*cc as f64, 0.0)).fft();
    let minus_big_f_fft = big_f.map(|cc| -Complex64::new(*cc as f64, 0.0)).fft();
    [g_fft, minus_f_fft, big_g_fft, minus_big_f_fft]
}

/// Encodes a sequence of signed integers such that each integer x satisfies |x| < 2^(bits-1)
/// for a given parameter bits. bits can take either the value 6 or 8.
pub fn encode_i8(x: &[i8], bits: usize) -> Option<Vec<u8>> {
    let maxv = (1 << (bits - 1)) - 1_usize;
    let maxv = maxv as i8;
    let minv = -maxv;

    for &c in x {
        if c > maxv || c < minv {
            return None;
        }
    }

    let out_len = ((N * bits) + 7) >> 3;
    let mut buf = vec![0_u8; out_len];

    let mut acc = 0_u32;
    let mut acc_len = 0;
    let mask = ((1_u16 << bits) - 1) as u8;

    let mut input_pos = 0;
    for &c in x {
        acc = (acc << bits) | (c as u8 & mask) as u32;
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[input_pos] = (acc >> acc_len) as u8;
            input_pos += 1;
        }
    }
    if acc_len > 0 {
        buf[input_pos] = (acc >> (8 - acc_len)) as u8;
    }

    Some(buf)
}

/// Decodes a sequence of bytes into a sequence of signed integers such that each integer x
/// satisfies |x| < 2^(bits-1) for a given parameter bits. bits can take either the value 6 or 8.
pub fn decode_i8(buf: &[u8], bits: usize) -> Option<Vec<i8>> {
    let mut x = [0_i8; N];

    let mut i = 0;
    let mut j = 0;
    let mut acc = 0_u32;
    let mut acc_len = 0;
    let mask = (1_u32 << bits) - 1;
    let a = (1 << bits) as u8;
    let b = ((1 << (bits - 1)) - 1) as u8;

    while i < N {
        acc = (acc << 8) | (buf[j] as u32);
        j += 1;
        acc_len += 8;

        while acc_len >= bits && i < N {
            acc_len -= bits;
            let w = (acc >> acc_len) & mask;

            let w = w as u8;

            let z = if w > b { w as i8 - a as i8 } else { w as i8 };

            x[i] = z;
            i += 1;
        }
    }

    if (acc & ((1u32 << acc_len) - 1)) == 0 {
        Some(x.to_vec())
    } else {
        None
    }
}
