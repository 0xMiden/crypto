use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, Signature,
    math::{FalconFelt, Polynomial},
};

mod public_key;
pub use public_key::PublicKey;

mod secret_key;
pub use secret_key::SecretKey;
pub(crate) use secret_key::{WIDTH_BIG_POLY_COEFFICIENT, WIDTH_SMALL_POLY_COEFFICIENT};

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{
        ONE, PrimeCharacteristicRing, Word,
        dsa::falcon512_rpo::SecretKey,
        utils::{Deserializable, Serializable},
    };

    #[test]
    fn test_falcon_verification() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // generate random keys
        let sk = SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let mut buffer = vec![];
        sk.write_into(&mut buffer);
        let sk_deserialized = SecretKey::read_from_bytes(&buffer).unwrap();
        assert_eq!(sk.short_lattice_basis(), sk_deserialized.short_lattice_basis());

        // sign a random message
        let message = Word::new([ONE; 4]);
        let signature = sk.sign_with_rng(message, &mut rng);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, &signature));

        // a signature should not verify against a wrong message
        let message2 = Word::new([ONE.double(); 4]);
        assert!(!pk.verify(message2, &signature));

        // a signature should not verify against a wrong public key
        let sk2 = SecretKey::with_rng(&mut rng);
        assert!(!sk2.public_key().verify(message, &signature))
    }

    #[test]
    fn test_flr_vs_legacy_signing_compatibility() {
        use super::super::Nonce;
        use super::super::hash_to_point::hash_to_point_rpo256;

        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // generate random keys
        let sk = SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // prepare message
        let message = Word::new([ONE; 4]);
        let nonce = Nonce::deterministic();
        let c = hash_to_point_rpo256(message, &nonce);

        // Create two RNGs with the same seed for deterministic comparison
        let mut rng_flr = ChaCha20Rng::from_seed([1u8; 32]);
        let mut rng_legacy = ChaCha20Rng::from_seed([1u8; 32]);

        // sign with FLR implementation
        let sig_flr = sk.sign_helper_flr(c.clone(), &mut rng_flr);

        // sign with legacy implementation using same RNG seed
        let sig_legacy = sk.sign_helper_legacy(c, &mut rng_legacy);

        // Extract coefficients for comparison
        let sig_flr_coef: Vec<i16> =
            sig_flr.coefficients.iter().map(|c| c.balanced_value()).collect();
        let sig_legacy_coef: Vec<i16> =
            sig_legacy.coefficients.iter().map(|c| c.balanced_value()).collect();

        // The two implementations should produce EXACTLY the same signature
        // given the same keys and RNG state
        assert_eq!(
            sig_flr_coef, sig_legacy_coef,
            "FLR and legacy implementations should produce identical signatures with same RNG"
        );

        // Verify the signature is valid
        let h = sk.public_key();
        let signature = super::super::Signature::new(nonce, h, sig_flr);
        assert!(pk.verify(message, &signature), "Signature should verify");
    }
}
