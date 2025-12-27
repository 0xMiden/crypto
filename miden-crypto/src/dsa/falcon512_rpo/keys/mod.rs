use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, Signature,
    math::{FalconFelt, Polynomial},
};

mod public_key;
pub use public_key::PublicKey;

mod secret_key;
pub use secret_key::SecretKey;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{
        ONE, PrimeCharacteristicRing, Word,
        dsa::falcon512_rpo::SecretKey,
        dsa::falcon512_rpo::PublicKey,
        utils::{Deserializable, Serializable},
    };

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Generate a public key from a secret key
        let sk = SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // Serialize and deserialize the public key
        let serialized = (&pk).to_bytes();
        let pk_deserialized = PublicKey::read_from_bytes(&serialized).unwrap();

        // Compare the original and deserialized public keys
        assert_eq!(pk, pk_deserialized);
    }

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
}
