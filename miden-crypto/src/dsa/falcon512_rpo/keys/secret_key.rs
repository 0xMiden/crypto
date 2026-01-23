use alloc::string::ToString;

use fn_dsa_kgen::{FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGenerator512};
use fn_dsa_sign::{SigningKey, SigningKey512};
use miden_crypto_derive::{SilentDebug, SilentDisplay};
use rand::{CryptoRng, Rng, RngCore};

use super::{
    super::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, N, Nonce, Serializable,
        Signature, signature::SignaturePoly,
    },
    PublicKey,
};
use crate::{
    Word,
    dsa::falcon512_rpo::{LOG_N, PK_LEN, SK_LEN, hash_to_point::hash_to_point_rpo256},
    utils::zeroize::{Zeroize, ZeroizeOnDrop},
};

// SECRET KEY
// ================================================================================================

/// Represents the secret key for Falcon DSA.
///
/// The secret key consists of four polynomials [f, g, F, G] that form a short basis for
/// an NTRU lattice. The public key h = g/f (mod q) can be derived from the secret key.
///
/// Internally, this stores the encoded secret key bytes in fn-dsa format. The bytes are
/// decoded to a `SigningKey512` on demand for signing operations.
///
/// [1]: https://falcon-sign.info/falcon.pdf
#[derive(Clone, SilentDebug, SilentDisplay)]
pub struct SecretKey {
    encoded: [u8; SK_LEN],
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.encoded.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

#[allow(clippy::new_without_default)]
impl SecretKey {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Generates a secret key from OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self::with_rng(&mut rng)
    }

    /// Generates a secret_key using the provided random number generator `Rng`.
    ///
    /// # Security Requirements
    ///
    /// The provided RNG must be cryptographically secure. Using a weak or predictable
    /// RNG will completely compromise security. Prefer [`SecretKey::new()`] which uses
    /// OS-provided randomness unless you have specific requirements for the RNG source.
    pub fn with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut kg = KeyPairGenerator512::default();
        let mut encoded = [0u8; SK_LEN];
        let mut vrfy_key = [0u8; PK_LEN];

        // Bridge our rand 0.9 RNG into fn-dsa's rand_core 0.6 traits expected by keygen.
        let mut adapter = FnDsaRng { rng };
        kg.keygen(FN_DSA_LOGN_512, &mut adapter, &mut encoded, &mut vrfy_key);

        // Zeroize vrfy_key buffer (encoded is kept)
        vrfy_key.zeroize();

        Self { encoded }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> PublicKey {
        let signing_key = self.decode_signing_key();
        let mut pk_bytes = [0u8; PK_LEN];
        signing_key.to_verifying_key(&mut pk_bytes);
        PublicKey::read_from_bytes(&pk_bytes).expect("fn-dsa produced valid public key bytes")
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Decodes the stored bytes into a SigningKey512 for signing operations.
    fn decode_signing_key(&self) -> SigningKey512 {
        SigningKey512::decode(&self.encoded).expect("encoded key should be valid")
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with this secret key using deterministic signing.
    ///
    /// The signing seed is derived from the message and secret key using BLAKE3,
    /// ensuring the same message always produces the same signature.
    pub fn sign(&self, message: Word) -> Signature {
        let mut seed = self.generate_signing_seed(&message);
        let sig = self.sign_with_seed(message, &seed);
        seed.zeroize();
        sig
    }

    /// Signs a message with the secret key using the provided randomness generator.
    ///
    /// The RNG is used to generate the 56-byte seed for the internal SHAKE256 PRNG.
    pub fn sign_with_rng<R: Rng>(&self, message: Word, rng: &mut R) -> Signature {
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let sig = self.sign_with_seed(message, &seed);
        seed.zeroize();
        sig
    }

    /// Signs a message using the provided 56-byte seed for the PRNG.
    ///
    /// Following FN-DSA, each signing attempt uses a fresh nonce and recomputes
    /// hash-to-point. A single PRNG seeded with the input generates both the
    /// sampler seed and nonces, ensuring reproducible signatures.
    fn sign_with_seed(&self, message: Word, seed: &[u8; 56]) -> Signature {
        use fn_dsa_comm::shake::SHAKE256;

        let h = self.public_key();
        let mut signing_key = self.decode_signing_key();

        // Initialize single PRNG from seed
        let mut prng = SHAKE256::new();
        prng.inject(seed);
        prng.flip();

        // Extract sampler seed first, then use same PRNG for nonces
        let mut sampler_seed = [0u8; 56];
        prng.extract(&mut sampler_seed);
        let mut sampler = signing_key.create_sampler(&sampler_seed);

        let mut sig_buf = [0u8; 666]; // signature_size(9) = 666

        loop {
            // Generate fresh nonce for this attempt
            let mut nonce_bytes = [0u8; 40];
            prng.extract(&mut nonce_bytes);
            let nonce = Nonce::from_bytes(nonce_bytes);

            // Compute hash-to-point with this nonce
            let c = hash_to_point_rpo256(message, &nonce);
            let hm: [u16; N] = core::array::from_fn(|i| c.coefficients[i].value());

            if signing_key.sign_attempt(&hm, &nonce_bytes, &mut sampler, &mut sig_buf) {
                // Decode s2 from the signature buffer
                // Signature format: header (1 byte) + nonce (40 bytes) + compressed s2
                let mut s2 = [0i16; N];
                fn_dsa_comm::codec::comp_decode(&sig_buf[41..], &mut s2);

                let s2_poly = SignaturePoly::try_from(&s2)
                    .expect("signature from sign_attempt should be valid");

                return Signature::new(nonce, h, s2_poly);
            }
            // On failure, sampler and PRNG have advanced - retry with new nonce
        }
    }

    /// Signs a byte message using SHAKE256 hash-to-point with a random nonce.
    ///
    /// This produces signatures compatible with fn-dsa, using:
    /// - SHAKE256-based hash-to-point (original Falcon)
    /// - Random 40-byte nonce per attempt (FN-DSA compliant)
    /// - SHAKE256 PRNG for Gaussian sampling
    ///
    /// Returns a tuple of (nonce, s2_coefficients) representing the raw signature components.
    pub fn sign_shake256<R: Rng>(&self, message: &[u8], rng: &mut R) -> ([u8; 40], [i16; N]) {
        use fn_dsa_comm::{DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON, shake::SHAKE256};

        let mut signing_key = self.decode_signing_key();

        // Generate random 56-byte seed and initialize PRNG
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);

        let mut prng = SHAKE256::new();
        prng.inject(&seed);
        prng.flip();
        seed.zeroize();

        // Extract sampler seed first, then use same PRNG for nonces
        let mut sampler_seed = [0u8; 56];
        prng.extract(&mut sampler_seed);
        let mut sampler = signing_key.create_sampler(&sampler_seed);

        // Compute hvk = SHAKE256(verification_key)
        let mut pk_bytes = [0u8; PK_LEN];
        signing_key.to_verifying_key(&mut pk_bytes);
        let mut hvk = [0u8; 64];
        {
            let mut sh = SHAKE256::new();
            sh.inject(&pk_bytes);
            sh.flip();
            sh.extract(&mut hvk);
        }

        let mut sig_buf = [0u8; 666];

        loop {
            // Generate fresh nonce for this attempt
            let mut nonce = [0u8; 40];
            prng.extract(&mut nonce);

            // Compute hash-to-point using SHAKE256
            let mut hm = [0u16; N];
            fn_dsa_comm::hash_to_point(
                &nonce,
                &hvk,
                &DOMAIN_NONE,
                &HASH_ID_ORIGINAL_FALCON,
                message,
                &mut hm,
            );

            if signing_key.sign_attempt(&hm, &nonce, &mut sampler, &mut sig_buf) {
                // Decode s2 from the signature buffer
                let mut s2 = [0i16; N];
                fn_dsa_comm::codec::comp_decode(&sig_buf[41..], &mut s2);
                return (nonce, s2);
            }
            // On failure, both PRNGs have advanced - retry with new nonce
        }
    }

    /// Generates a 56-byte signing seed from the message and secret key.
    ///
    /// Uses BLAKE3 in XOF mode to derive a deterministic seed for the PRNG.
    fn generate_signing_seed(&self, message: &Word) -> [u8; 56] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[LOG_N]);
        hasher.update(&self.encoded);
        hasher.update(&message.to_bytes());

        let mut seed = [0u8; 56];
        hasher.finalize_xof().fill(&mut seed);

        seed
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.encoded.ct_eq(&other.encoded).into()
    }
}

impl Eq for SecretKey {}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.encoded);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let encoded: [u8; SK_LEN] = source.read_array()?;

        // Validate the encoded bytes by attempting to decode
        SigningKey512::decode(&encoded)
            .ok_or(DeserializationError::InvalidValue("Failed to decode secret key".to_string()))?;

        Ok(Self { encoded })
    }
}

// HELPER TYPES
// ================================================================================================

/// Adapts a rand 0.9 RNG to the rand_core 0.6 traits expected by fn-dsa keygen.
struct FnDsaRng<'a, R: RngCore + CryptoRng> {
    rng: &'a mut R,
}

impl<R: RngCore + CryptoRng> fn_dsa_comm::RngCore for FnDsaRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> core::result::Result<(), fn_dsa_comm::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng> fn_dsa_comm::CryptoRng for FnDsaRng<'_, R> {}
