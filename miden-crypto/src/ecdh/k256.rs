//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementation over k256
//! i.e., secp256k1 curve.
//!
//! Note that the intended use is in the context of a one-way, sender initiated key agreement
//! scenario. Namely, when the sender knows the (static) public key of the receiver and it
//! uses that, together with an ephemeral secret key that it generates, to derive a shared
//! secret.
//!
//! This shared secret will then be used to encrypt some message (using for example a key
//! derivation function).
//!
//! The public key associated with the ephemeral secret key will be sent alongside the encrypted
//! message.

use alloc::string::ToString;

use hkdf::{Hkdf, hmac::SimpleHmac};
use k256::{AffinePoint, elliptic_curve::sec1::ToEncodedPoint, sha2::Sha256};
use rand::{CryptoRng, RngCore};

use crate::{
    dsa::ecdsa_k256_keccak::{PUBLIC_KEY_BYTES, PublicKey},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A shared secret computed using the ECDH (Elliptic Curve Diffie-Hellman) key agreement.
pub struct SharedSecret {
    pub(crate) inner: k256::ecdh::SharedSecret,
}

impl SharedSecret {
    pub(crate) fn new(inner: k256::ecdh::SharedSecret) -> SharedSecret {
        Self { inner }
    }

    /// Returns a HKDF (HMAC-based Extract-and-Expand Key Derivation Function) that can be used
    /// to extract entropy from the shared secret.
    ///
    /// This basically converts a shared secret into uniformly random values that are appropriate
    /// for use as key material.
    pub fn extract<D>(&self, salt: Option<&[u8]>) -> Hkdf<Sha256, SimpleHmac<Sha256>> {
        self.inner.extract(salt)
    }
}

/// Ephemeral secret key for ECDH key agreement over secp256k1 curve.
pub struct EphemeralSecretKey {
    inner: k256::ecdh::EphemeralSecret,
}

impl EphemeralSecretKey {
    /// Generates a new random ephemeral secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();

        Self::with_rng(&mut rng)
    }

    /// Generates a new ephemeral secret key using the provided random number generator.
    pub fn with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        // we use a seedable CSPRNG and seed it with `rng`
        // this is a work around the fact that the version of the `rand` dependency in our crate
        // is different than the one used in the `k256` one. This solution will no longer be needed
        // once `k256` gets a new release with a version of the `rand` dependency matching ours
        use k256::elliptic_curve::rand_core::SeedableRng;
        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(rng, &mut seed);
        let mut rng = rand_hc::Hc128Rng::from_seed(seed);

        let sk_e = k256::ecdh::EphemeralSecret::random(&mut rng);
        Self { inner: sk_e }
    }

    /// Gets the corresponding ephemeral public key for this ephemeral secret key.
    pub fn public_key(&self) -> EphemeralPublicKey {
        let pk = self.inner.public_key();
        EphemeralPublicKey { inner: pk }
    }

    /// Computes a Diffie-Hellman shared secret from an ephemeral secret key and the (static) public
    /// key of the other party.
    pub fn diffie_hellman(&self, pk_other: PublicKey) -> SharedSecret {
        let shared_secret_inner = self.inner.diffie_hellman(&pk_other.inner.into());

        SharedSecret { inner: shared_secret_inner }
    }
}

/// Ephemeral public key for ECDH key agreement over secp256k1 curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    pub(crate) inner: k256::PublicKey,
}

impl EphemeralPublicKey {
    /// Returns a reference to this ephemeral public key as an elliptic curve point in affine
    /// coordinates.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }
}

impl Serializable for EphemeralPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Compressed format
        let encoded = self.inner.to_encoded_point(true);

        target.write_bytes(encoded.as_bytes());
    }
}

impl Deserializable for EphemeralPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; PUBLIC_KEY_BYTES] = source.read_array()?;

        let inner = k256::PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("Invalid public key".to_string()))?;

        Ok(Self { inner })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use rand::rng;
    use winter_utils::{Deserializable, Serializable};

    use super::{EphemeralPublicKey, EphemeralSecretKey};
    use crate::dsa::ecdsa_k256_keccak::SecretKey;

    #[test]
    fn key_agreement() {
        let mut rng = rng();

        // 1. Generate the static key-pair for Alice
        let sk = SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // 2. Generate the ephemeral key-pair for Bob
        let sk_e = EphemeralSecretKey::with_rng(&mut rng);
        let pk_e = sk_e.public_key();

        // 3. Bob computes the shared secret key (Bob will send pk_e with the encrypted note to
        //    Alice)
        let shared_secret_key_1 = sk_e.diffie_hellman(pk.into());

        // 4. Alice uses its secret key and the ephemeral public key sent with the encrypted note by
        //    Bob in order to create the shared secret key. This shared secet key will be used to
        //    decrypt the encrypted note
        let shared_secret_key_2 = sk.get_shared_secret(pk_e.into());

        // Check that the computed shared secret keys are equal
        assert_eq!(
            shared_secret_key_1.inner.raw_secret_bytes(),
            shared_secret_key_2.inner.raw_secret_bytes()
        );
    }

    #[test]
    fn test_serialization_round_trip() {
        let mut rng = rng();

        let sk_e = EphemeralSecretKey::with_rng(&mut rng);
        let pk_e = sk_e.public_key();

        let pk_e_bytes = pk_e.to_bytes();
        let pk_e_serialized = EphemeralPublicKey::read_from_bytes(&pk_e_bytes)
            .expect("failed to desrialize ephemeral public key");
        assert_eq!(pk_e_serialized, pk_e);
    }
}
