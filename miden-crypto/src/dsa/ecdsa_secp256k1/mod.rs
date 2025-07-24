//! ECDSA (Elliptic Curve Digital Signature Algorithm) signature implementation over secp256k1
//! curve.

use alloc::{string::ToString, vec::Vec};

use k256::{
    ecdsa::{
        SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
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
const SIGNATURE_BYTES: usize = 64;

// SECRET KEY
// ================================================================================================

/// Secret key for ECDSA signature verification over secp256k1 curve.
#[derive(Clone)]
pub struct SecretKey {
    inner: SigningKey,
}

impl SecretKey {
    /// Generate a new random secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;

        Self::with_rng(&mut rng)
    }

    /// Generate a new secret key using the provided random number generator.
    pub fn with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let signing_key = SigningKey::random(rng);
        Self { inner: signing_key }
    }

    /// Get the corresponding public key for this secret key.
    pub fn public_key(&self) -> PublicKey {
        let verifying_key = self.inner.verifying_key();
        PublicKey { inner: *verifying_key }
    }

    /// Sign a message (represented as a Word) with this secret key.
    pub fn sign(&mut self, message: Word) -> Signature {
        // Convert Word to bytes for signing
        let message_bytes: [u8; 32] = message.into();

        // Sign the message
        let signature: k256::ecdsa::Signature = self.inner.sign(&message_bytes);

        Signature { inner: signature }
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

    /// Verify a signature against this public key and message.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        let message_bytes: [u8; 32] = message.into();
        self.inner.verify(&message_bytes, &signature.inner).is_ok()
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

/// ECDSA signature over secp256k1 curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    inner: k256::ecdsa::Signature,
}

impl Signature {
    /// Verify this signature against a message and public key..
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
        let bytes: [u8; SIGNATURE_BYTES] = self.inner.to_bytes().into();
        target.write_bytes(&bytes);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; SIGNATURE_BYTES] = source.read_array()?;

        let signature = k256::ecdsa::Signature::from_slice(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("Invalid public key".to_string()))?;

        Ok(Self { inner: signature })
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
    fn test_sign_and_verify() {
        let mut secret_key = SecretKey::with_rng(&mut OsRng);
        let public_key = secret_key.public_key();

        let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let signature = secret_key.sign(message);

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
        let signature = secret_key.sign(message);

        let sig_bytes = signature.to_bytes();
        let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, recovered_sig);
    }
}
