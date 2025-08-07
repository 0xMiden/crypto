//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementation over secp256k1 curve.
//!
//! Note that the intended use is in the context of a one-way, sender initiated key agreement
//! scenario. Namely, when the sender knows the (static) public key of the receiver and it
//! uses that, together with an ephemeral secret key that it generates, to derive a shared
//! secret.
//! This shared secret will then be used to encrypt some message (using for example a key
//! derivation function).
//! The public key associated with the ephemeral secret key will be sent alongside the encrypted
//! message.

use hkdf::{Hkdf, hmac::SimpleHmac};
use k256::{
    AffinePoint,
    elliptic_curve::rand_core::{CryptoRng, RngCore},
    sha2::Sha256,
};

use super::PublicKey;

/// A shared secret computed using the ECDH (Elliptic Curve Diffie-Hellman) key agreement.
pub struct SharedSecret {
    inner: k256::ecdh::SharedSecret,
}

impl SharedSecret {
    /// Returns a HKDF (HMAC-based Extract-and-Expand Key Derivation Function) that can be used
    /// to extract entropy from the shared secret.
    /// This basically converts a shared secret into uniformly random values that are appropriate
    /// for use as key material.
    pub fn extract<D>(&self, salt: Option<&[u8]>) -> Hkdf<Sha256, SimpleHmac<Sha256>> {
        self.inner.extract(salt)
    }

    pub(crate) fn from_inner(inner: k256::ecdh::SharedSecret) -> SharedSecret {
        Self { inner }
    }
}

/// Ephemeral public key for ECDH key agreement over secp256k1 curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    inner: k256::PublicKey,
}

impl EphemeralPublicKey {
    /// Returns a reference to this ephemeral public key as an elliptic curve point in affine
    /// coordinates.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
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
        let mut rng = k256::elliptic_curve::rand_core::OsRng;

        Self::with_rng(&mut rng)
    }

    /// Generates a new ephemeral secret key using the provided random number generator.
    pub fn with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let sk_e = k256::ecdh::EphemeralSecret::random(rng);
        Self { inner: sk_e }
    }

    /// Gets the corresponding ephemeral public key for this ephemeral secret key.
    pub fn ephemeral_public_key(&self) -> EphemeralPublicKey {
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

#[cfg(test)]
mod test {
    use k256::elliptic_curve::rand_core::OsRng;

    use crate::dsa::ecdsa_secp256k1::{SecretKey, key_agreement::EphemeralSecretKey};

    #[test]
    fn key_agreement() {
        // 1. Generate the static key-pair for Alice
        let sk = SecretKey::with_rng(&mut OsRng);
        let pk = sk.public_key();

        // 2. Generate the ephemeral key-pair for Bob
        let sk_e = EphemeralSecretKey::with_rng(&mut OsRng);
        let pk_e = sk_e.ephemeral_public_key();

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
}
