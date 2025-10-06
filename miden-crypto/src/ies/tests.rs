use alloc::vec::Vec;

use crate::{
    dsa::{ecdsa_k256_keccak::SecretKey, eddsa_25519::SecretKey as SecretKey25519},
    ies::{keys::EphemeralPublicKey, *},
};

#[test]
fn test_sealing_and_unsealing_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = b"roundtrip";
    let ad = b"ctx";

    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

    let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
    let decrypted = unsealing_key.unseal_with_associated_data(sealed, ad).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_invalid_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"with ad";
    let ad = b"good";
    let bad_ad = b"bad";

    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

    let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
    let result = unsealing_key.unseal_with_associated_data(sealed, bad_ad);

    assert!(result.is_err());
}

#[test]
fn test_sealing_and_unsealing_roundtrip_x25519() {
    let mut rng = rand::rng();
    let plaintext = b"roundtrip-x25519";
    let ad = b"ctx-x25519";

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

    let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
    let decrypted = unsealing_key.unseal_with_associated_data(sealed, ad).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_invalid_associated_data_x25519() {
    let mut rng = rand::rng();
    let plaintext = b"with ad x25519";
    let ad = b"good-x25519";
    let bad_ad = b"bad-x25519";

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, plaintext, ad).unwrap();

    let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
    let result = unsealing_key.unseal_with_associated_data(sealed, bad_ad);

    assert!(result.is_err());
}

#[test]
fn test_ephemeral_public_key_serialization_roundtrip_k256() {
    let mut rng = rand::rng();
    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();
    let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, b"msg", b"ad").unwrap();

    let original = sealed.ephemeral_key.clone();
    let bytes = original.to_bytes();
    let restored = EphemeralPublicKey::from_bytes(original.algorithm(), &bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_ephemeral_public_key_serialization_roundtrip_x25519() {
    let mut rng = rand::rng();
    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();
    let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal_with_associated_data(&mut rng, b"msg", b"ad").unwrap();

    let original = sealed.ephemeral_key.clone();
    let bytes = original.to_bytes();
    let restored = EphemeralPublicKey::from_bytes(original.algorithm(), &bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_field_element_sealing_and_unsealing_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(1), crate::Felt::new(2), crate::Felt::new(3)];
    let associated_data = vec![crate::Felt::new(100), crate::Felt::new(200)];

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519AeadRpo(public_key);
    let sealed = sealing_key
        .seal_elements_with_associated_data(&mut rng, &plaintext, &associated_data)
        .unwrap();

    let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
    let decrypted = unsealing_key
        .unseal_elements_with_associated_data(sealed, &associated_data)
        .unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_field_element_sealing_without_associated_data() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(42), crate::Felt::new(84), crate::Felt::new(126)];

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519AeadRpo(public_key);
    let sealed = sealing_key.seal_elements(&mut rng, &plaintext).unwrap();

    let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
    let decrypted = unsealing_key.unseal_elements(sealed).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_x25519_rpo256_bytes_compatibility() {
    let mut rng = rand::rng();
    let byte_data = b"Hello, field elements!";

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519AeadRpo(public_key);
    let sealed = sealing_key.seal(&mut rng, byte_data).unwrap();

    let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
    let decrypted = unsealing_key.unseal(sealed).unwrap();

    assert_eq!(byte_data, decrypted.as_slice());
}

#[test]
fn test_k256_seal_unseal_without_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"test message k256";

    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal(&mut rng, plaintext).unwrap();

    let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
    let decrypted = unsealing_key.unseal(sealed).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_x25519_xchacha_seal_unseal_without_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"test message x25519 xchacha";

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
    let sealed = sealing_key.seal(&mut rng, plaintext).unwrap();

    let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
    let decrypted = unsealing_key.unseal(sealed).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_x25519_rpo_seal_unseal_without_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"test message x25519 rpo";

    let secret_key = SecretKey25519::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealing_key = SealingKey::X25519AeadRpo(public_key);
    let sealed = sealing_key.seal(&mut rng, plaintext).unwrap();

    let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
    let decrypted = unsealing_key.unseal(sealed).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

// PROPERTY-BASED TESTS
// ================================================================================================

use proptest::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Generates arbitrary byte vectors using the same pattern as existing AEAD tests
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..500)
}

/// Generates arbitrary field element vectors using the same pattern as AEAD tests
fn arbitrary_field_elements() -> impl Strategy<Value = Vec<crate::Felt>> {
    (1usize..100, any::<u64>()).prop_map(|(len, seed)| {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..len).map(|_| crate::Felt::new(rng.next_u64())).collect()
    })
}

/// Helper macro for basic IES roundtrip testing
macro_rules! test_roundtrip {
    (
        $sealing_key:expr,
        $unsealing_key:expr,
        $plaintext:expr,
        $seal_method:ident,
        $unseal_method:ident
    ) => {
        let mut rng = rand::rng();
        let sealed = $sealing_key.$seal_method(&mut rng, $plaintext).unwrap();
        let decrypted = $unsealing_key.$unseal_method(sealed).unwrap();
        prop_assert_eq!($plaintext.clone(), decrypted);
    };
    (
        $sealing_key:expr,
        $unsealing_key:expr,
        $plaintext:expr,
        $associated_data:expr,
        $seal_method:ident,
        $unseal_method:ident
    ) => {
        let mut rng = rand::rng();
        let sealed = $sealing_key.$seal_method(&mut rng, $plaintext, $associated_data).unwrap();
        let decrypted = $unsealing_key.$unseal_method(sealed, $associated_data).unwrap();
        prop_assert_eq!($plaintext.clone(), decrypted);
    };
}

proptest! {
    #[test]
    fn prop_k256_bytes_roundtrip(
        plaintext in arbitrary_bytes(),
        associated_data in arbitrary_bytes()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);

        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_with_associated_data, unseal_with_associated_data);
    }

    #[test]
    fn prop_x25519_xchacha_bytes_roundtrip(
        plaintext in arbitrary_bytes(),
        associated_data in arbitrary_bytes()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);

        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_with_associated_data, unseal_with_associated_data);
    }

    #[test]
    fn prop_x25519_rpo_bytes_roundtrip(
        plaintext in arbitrary_bytes(),
        associated_data in arbitrary_bytes()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);

        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_with_associated_data, unseal_with_associated_data);
    }

    #[test]
    fn prop_x25519_rpo_elements_roundtrip(
        plaintext in arbitrary_field_elements(),
        associated_data in arbitrary_field_elements()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);

        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_elements_with_associated_data, unseal_elements_with_associated_data);
    }

    #[test]
    fn prop_algorithm_mismatch_detection(
        plaintext in arbitrary_bytes()
    ) {
        let mut rng = rand::rng();

        // Create keys for different algorithms
        let secret_k256 = SecretKey::with_rng(&mut rng);
        let public_k256 = secret_k256.public_key();
        let secret_x25519 = SecretKey25519::with_rng(&mut rng);

        // Seal with K256
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_k256);
        let sealed = sealing_key.seal(&mut rng, &plaintext).unwrap();

        // Try to unseal with X25519 - should fail
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_x25519);
        let result = unsealing_key.unseal(sealed);

        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_wrong_associated_data_detection(
        plaintext in arbitrary_bytes(),
        correct_ad in arbitrary_bytes(),
        wrong_ad in arbitrary_bytes()
    ) {
        // Skip test if associated data is the same
        prop_assume!(correct_ad != wrong_ad);

        let mut rng = rand::rng();

        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let sealed = sealing_key.seal_with_associated_data(&mut rng, &plaintext, &correct_ad).unwrap();

        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        let result = unsealing_key.unseal_with_associated_data(sealed, &wrong_ad);

        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_different_keys_different_ciphertexts(
        plaintext in arbitrary_bytes()
    ) {
        prop_assume!(!plaintext.is_empty()); // Skip empty plaintexts

        let mut rng = rand::rng();

        // Generate two different key pairs
        let secret1 = SecretKey25519::with_rng(&mut rng);
        let public1 = secret1.public_key();
        let secret2 = SecretKey25519::with_rng(&mut rng);
        let public2 = secret2.public_key();

        let sealing_key1 = SealingKey::X25519AeadRpo(public1);
        let sealing_key2 = SealingKey::X25519AeadRpo(public2);

        let sealed1 = sealing_key1.seal(&mut rng, &plaintext).unwrap();
        let sealed2 = sealing_key2.seal(&mut rng, &plaintext).unwrap();

        // Different keys should produce different ciphertexts
        prop_assert_ne!(sealed1.ciphertext, sealed2.ciphertext);
    }

    #[test]
    fn prop_seal_without_ad_consistency(
        plaintext in arbitrary_bytes()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);

        // Test both seal methods work for the same plaintext
        test_roundtrip!(sealing_key, unsealing_key, &plaintext, seal, unseal);
        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &Vec::<u8>::new(), seal_with_associated_data, unseal_with_associated_data);
    }

    #[test]
    fn prop_field_elements_consistency(
        plaintext in arbitrary_field_elements()
    ) {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);

        // Test both seal methods work for the same field elements
        test_roundtrip!(sealing_key, unsealing_key, &plaintext, seal_elements, unseal_elements);
        test_roundtrip!(sealing_key, unsealing_key, &plaintext, &Vec::<crate::Felt>::new(), seal_elements_with_associated_data, unseal_elements_with_associated_data);
    }
}
