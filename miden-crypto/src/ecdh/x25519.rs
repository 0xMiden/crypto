//! X25519 (Elliptic Curve Diffie-Hellman) key agreement implementation using
//! Curve25519.
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

use hkdf::{Hkdf, hmac::SimpleHmac};
use k256::sha2::Sha256;
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{
    dsa::eddsa_25519::PublicKey,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A shared secret computed using the X25519 (Elliptic Curve Diffie-Hellman) key agreement.
///
/// This type implements `ZeroizeOnDrop` because the inner `x25519_dalek::SharedSecret`
/// implements it, ensuring the shared secret is securely wiped from memory when dropped.
pub struct SharedSecret {
    pub(crate) inner: x25519_dalek::SharedSecret,
}
impl SharedSecret {
    pub(crate) fn new(inner: x25519_dalek::SharedSecret) -> SharedSecret {
        Self { inner }
    }

    /// Returns a HKDF that can be used to derive uniform keys from the shared secret.
    pub fn extract(&self, salt: Option<&[u8]>) -> Hkdf<Sha256, SimpleHmac<Sha256>> {
        Hkdf::new(salt, self.inner.as_bytes())
    }
}

// Safe to derive ZeroizeOnDrop because the inner field already implements it.
impl ZeroizeOnDrop for SharedSecret {}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Ephemeral secret key for X25519 key agreement.
///
/// This type implements `ZeroizeOnDrop` because the inner `x25519_dalek::EphemeralSecret`
/// implements it, ensuring the secret key material is securely wiped from memory when dropped.
pub struct EphemeralSecretKey {
    inner: x25519_dalek::EphemeralSecret,
}

impl ZeroizeOnDrop for EphemeralSecretKey {}

impl EphemeralSecretKey {
    /// Generates a new random ephemeral secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();

        Self::with_rng(&mut rng)
    }

    /// Generates a new random ephemeral secret key using the provided RNG.
    pub fn with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        // we use a seedable CSPRNG and seed it with `rng`
        // this is a work around the fact that the version of the `rand` dependency in our crate
        // is different than the one used in the `x25519_dalek` one. This solution will no longer be
        // needed once `x25519_dalek` gets a new release with a version of the `rand`
        // dependency matching ours
        use k256::elliptic_curve::rand_core::SeedableRng;
        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(rng, &mut seed);
        let rng = rand_hc::Hc128Rng::from_seed(seed);

        let sk = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        Self { inner: sk }
    }

    /// Returns the corresponding ephemeral public key.
    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey {
            inner: x25519_dalek::PublicKey::from(&self.inner),
        }
    }

    /// Computes a Diffie-Hellman shared secret from this ephemeral secret key and the other party's
    /// static public key.
    pub fn diffie_hellman(self, pk_other: &PublicKey) -> SharedSecret {
        let shared = self.inner.diffie_hellman(&pk_other.to_x25519());
        SharedSecret::new(shared)
    }
}

/// Ephemeral public key for X25519 agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    pub(crate) inner: x25519_dalek::PublicKey,
}

impl Serializable for EphemeralPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.inner.as_bytes());
    }
}

impl Deserializable for EphemeralPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; 32] = source.read_array()?;
        Ok(Self {
            inner: x25519_dalek::PublicKey::from(bytes),
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::rng;

    use super::*;
    use crate::dsa::eddsa_25519::SecretKey;

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
        let shared_secret_key_1 = sk_e.diffie_hellman(&pk);

        // 4. Alice uses its secret key and the ephemeral public key sent with the encrypted note by
        //    Bob in order to create the shared secret key. This shared secret key will be used to
        //    decrypt the encrypted note
        let shared_secret_key_2 = sk.get_shared_secret(pk_e);

        // Check that the computed shared secret keys are equal
        assert_eq!(shared_secret_key_1.inner.to_bytes(), shared_secret_key_2.inner.to_bytes());
    }
}
