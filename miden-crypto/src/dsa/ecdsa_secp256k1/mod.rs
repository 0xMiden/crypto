//! ECDSA (Elliptic Curve Digital Signature Algorithm) signature implementation over secp256k1
//! curve.

use alloc::{string::ToString, vec::Vec};

use k256::{
    ecdsa::{RecoveryId, SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::rand_core::{CryptoRng, RngCore},
};

use crate::{
    Felt, SequentialCommit, StarkField, Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

const SECRET_KEY_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 33; // we use the compressed format
const SIGNATURE_BYTES: usize = 66;
const SCALARS_SIZE_BYTES: usize = 32;

// ECDSA HASHER
// ================================================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EcdsaHasher {
    Sha256 = 0,
    Keccak = 1,
}

impl EcdsaHasher {
    /// Hashes a message using the variant of the ECDSA hasher.
    fn hash(&self, message: &[u8]) -> [u8; 32] {
        match self {
            EcdsaHasher::Sha256 => {
                use k256::sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(message);
                hasher.finalize().into()
            },
            EcdsaHasher::Keccak => {
                use sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();
                hasher.update(message);
                hasher.finalize().into()
            },
        }
    }

    /// Converts the hasher variant to a `u8`.
    pub fn to_byte(&self) -> u8 {
        *self as u8
    }

    /// Converts a `u8` to its corresponding hasher variant.
    pub fn from_byte(byte: u8) -> Option<Self> {
        if byte <= 1 {
            Some(unsafe { std::mem::transmute::<u8, EcdsaHasher>(byte) })
        } else {
            None
        }
    }
}

// SECRET KEY
// ================================================================================================

/// Secret key for ECDSA signature verification over secp256k1 curve.
#[derive(Clone)]
pub struct SecretKey {
    inner: SigningKey,
}

impl SecretKey {
    /// Generates a new random secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;

        Self::with_rng(&mut rng)
    }

    /// Generates a new secret key using the provided random number generator.
    pub fn with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let signing_key = SigningKey::random(rng);
        Self { inner: signing_key }
    }

    /// Gets the corresponding public key for this secret key.
    pub fn public_key(&self) -> PublicKey {
        let verifying_key = self.inner.verifying_key();
        PublicKey { inner: *verifying_key }
    }

    /// Signs a message (represented as a Word) with this secret key.
    pub fn sign(&mut self, message: Word, hasher: EcdsaHasher) -> Signature {
        let message_bytes: [u8; 32] = message.into();
        let message_digest = hasher.hash(&message_bytes);

        let (signature_inner, recovery_id) = self
            .inner
            .sign_prehash_recoverable(&message_digest)
            .expect("failed to generate signature");

        let (r, s) = signature_inner.split_scalars();
        let signature_data = SignatureData {
            r: r.to_bytes().into(),
            s: s.to_bytes().into(),
            v: recovery_id.into(),
        };

        match hasher {
            EcdsaHasher::Sha256 => Signature::Sha256(signature_data),
            EcdsaHasher::Keccak => Signature::Keccak(signature_data),
        }
    }
}

// PUBLIC KEY
// ================================================================================================

/// Public key for ECDSA signature verification over secp256k1 curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    /// Returns a commitment to the public key using the RPO256 hash function.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Verifies a signature against this public key and message.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        let message_bytes: [u8; 32] = message.into();
        let message_digest = signature.hasher().hash(&message_bytes);
        let signature_inner = k256::ecdsa::Signature::from_scalars(*signature.r(), *signature.s());

        match signature_inner {
            Ok(signature) => self.inner.verify_prehash(&message_digest, &signature).is_ok(),
            Err(_) => false,
        }
    }

    /// Recovers from the signature the public key associated to the secret key used to sign the
    /// message.
    pub fn recover_from(message: Word, signature: &Signature) -> Self {
        let message_bytes: [u8; 32] = message.into();
        let message_digest = signature.hasher().hash(&message_bytes);
        let signature_data = k256::ecdsa::Signature::from_scalars(*signature.r(), *signature.s())
            .expect("could not build the signature from the scalars");

        let verifying_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &message_digest,
            &signature_data,
            RecoveryId::from_byte(signature.v()).expect("invalid recovery id"),
        )
        .expect("failed to recover the public key from the message and signature");

        Self { inner: verifying_key }
    }
}

impl SequentialCommit for PublicKey {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        self.to_bytes().chunks(7).map(Felt::from_bytes_with_padding).collect()
    }
}

// SIGNATURE
// ================================================================================================

/// ECDSA signature over secp256k1 curve using either SHA256 or Keccak to hash the messages when
/// signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Sha256(SignatureData),
    Keccak(SignatureData),
}

/// ECDSA signature over secp256k1 curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
    r: [u8; SCALARS_SIZE_BYTES],
    s: [u8; SCALARS_SIZE_BYTES],
    v: u8,
}

impl Signature {
    /// Returns the hasher associated to this signature.
    pub fn hasher(&self) -> EcdsaHasher {
        match self {
            Signature::Sha256(_) => EcdsaHasher::Sha256,
            Signature::Keccak(_) => EcdsaHasher::Keccak,
        }
    }

    /// Returns the `r` scalar of this signature.
    pub fn r(&self) -> &[u8; SCALARS_SIZE_BYTES] {
        match self {
            Signature::Sha256(SignatureData { r, .. }) => r,
            Signature::Keccak(SignatureData { r, .. }) => r,
        }
    }

    /// Returns the `s` scalar of this signature.
    pub fn s(&self) -> &[u8; SCALARS_SIZE_BYTES] {
        match self {
            Signature::Sha256(SignatureData { s, .. }) => s,
            Signature::Keccak(SignatureData { s, .. }) => s,
        }
    }

    /// Returns the `v` component of this signature, which is a `u8` representing the recovery id.
    pub fn v(&self) -> u8 {
        match self {
            Signature::Sha256(SignatureData { v, .. }) => *v,
            Signature::Keccak(SignatureData { v, .. }) => *v,
        }
    }

    /// Verifies this signature against a message and public key.
    pub fn verify(&self, message: Word, pub_key: &PublicKey) -> bool {
        pub_key.verify(message, self)
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut buffer = Vec::with_capacity(SECRET_KEY_BYTES);
        let sk_bytes: [u8; SECRET_KEY_BYTES] = self.inner.to_bytes().into();
        buffer.extend_from_slice(&sk_bytes);

        target.write_bytes(&buffer);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; SECRET_KEY_BYTES] = source.read_array()?;

        let signing_key = SigningKey::from_slice(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("Invalid secret key".to_string()))?;

        Ok(Self { inner: signing_key })
    }
}

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Compressed format
        let encoded = self.inner.to_encoded_point(true);

        target.write_bytes(encoded.as_bytes());
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; PUBLIC_KEY_BYTES] = source.read_array()?;

        let verifying_key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("Invalid public key".to_string()))?;

        Ok(Self { inner: verifying_key })
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        bytes[0..SCALARS_SIZE_BYTES].copy_from_slice(self.r());
        bytes[SCALARS_SIZE_BYTES..2 * SCALARS_SIZE_BYTES].copy_from_slice(self.s());
        bytes[2 * SCALARS_SIZE_BYTES] = self.v();
        bytes[2 * SCALARS_SIZE_BYTES + 1] = self.hasher().to_byte();
        target.write_bytes(&bytes);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let r: [u8; SCALARS_SIZE_BYTES] = source.read_array()?;
        let s: [u8; SCALARS_SIZE_BYTES] = source.read_array()?;
        let v: u8 = source.read_u8()?;

        let signature = SignatureData { r, s, v };

        let hasher =
            EcdsaHasher::from_byte(source.read_u8()?).expect("Not a valid EcdsaHasher variant");
        match hasher {
            EcdsaHasher::Sha256 => Ok(Signature::Sha256(signature)),
            EcdsaHasher::Keccak => Ok(Signature::Keccak(signature)),
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;
    use crate::Felt;

    #[test]
    fn test_key_generation() {
        let secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        // Test that we can convert to/from bytes
        let sk_bytes = secret_key.to_bytes();
        let recovered_sk = SecretKey::read_from_bytes(&sk_bytes).unwrap();
        assert_eq!(secret_key.to_bytes(), recovered_sk.to_bytes());

        let pk_bytes = public_key.to_bytes();
        let recovered_pk = PublicKey::read_from_bytes(&pk_bytes).unwrap();
        assert_eq!(public_key, recovered_pk);
    }

    #[test]
    fn test_public_key_recovery_sha256() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        // Generate a signature using the secret key
        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message, EcdsaHasher::Sha256);

        // Recover the public key
        let recovered_pk = PublicKey::recover_from(message, &signature);
        assert_eq!(public_key, recovered_pk);

        // Using the wrong message, we shouldn't be able to recover the public key
        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(5)].into();
        let recovered_pk = PublicKey::recover_from(message, &signature);
        assert!(public_key != recovered_pk);
    }

    #[test]
    fn test_public_key_recovery_keccak() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        // Generate a signature using the secret key
        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message, EcdsaHasher::Keccak);

        // Recover the public key
        let recovered_pk = PublicKey::recover_from(message, &signature);
        assert_eq!(public_key, recovered_pk);

        // Using the wrong message, we shouldn't be able to recover the public key
        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(5)].into();
        let recovered_pk = PublicKey::recover_from(message, &signature);
        assert!(public_key != recovered_pk);
    }

    #[test]
    fn test_sign_and_verify_sha256() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message, EcdsaHasher::Sha256);

        // Verify using public key method
        assert!(public_key.verify(message, &signature));

        // Verify using signature method
        assert!(signature.verify(message, &public_key));

        // Test with wrong message
        let wrong_message = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();
        assert!(!public_key.verify(wrong_message, &signature));
    }

    #[test]
    fn test_sign_and_verify_keccak() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message, EcdsaHasher::Keccak);

        // Verify using public key method
        assert!(public_key.verify(message, &signature));

        // Verify using signature method
        assert!(signature.verify(message, &public_key));

        // Test with wrong message
        let wrong_message = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();
        assert!(!public_key.verify(wrong_message, &signature));
    }

    #[test]
    fn test_signature_serialization() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message, EcdsaHasher::Sha256);

        let sig_bytes = signature.to_bytes();
        let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, recovered_sig);
    }
}
