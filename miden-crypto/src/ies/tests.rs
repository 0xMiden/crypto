use alloc::vec::Vec;

use proptest::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{
    dsa::{ecdsa_k256_keccak::SecretKey, eddsa_25519::SecretKey as SecretKey25519},
    ies::{keys::EphemeralPublicKey, *},
};

// CORE TEST INFRASTRUCTURE
// ================================================================================================

/// Generates arbitrary byte vectors for property testing
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..500)
}

/// Generates arbitrary field element vectors for property testing
fn arbitrary_field_elements() -> impl Strategy<Value = Vec<crate::Felt>> {
    (1usize..100, any::<u64>()).prop_map(|(len, seed)| {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..len).map(|_| crate::Felt::new(rng.next_u64())).collect()
    })
}

/// Helper macro for property-based roundtrip testing
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

/// Helper macro for basic roundtrip testing
macro_rules! test_basic_roundtrip {
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
        assert_eq!($plaintext, decrypted.as_slice());
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
        assert_eq!($plaintext, decrypted.as_slice());
    };
}

// IES SCHEME VARIANT REGISTRY
// ================================================================================================
// Each IES variant gets its own dedicated test module with comprehensive coverage
// To add a new variant, create a new module following the pattern below

/// K256 + XChaCha20-Poly1305 test suite
mod k256_xchacha_tests {
    use super::*;

    #[test]
    fn test_k256_xchacha_bytes_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes encryption";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(sealing_key, unsealing_key, plaintext, seal_bytes, unseal_bytes);
    }

    #[test]
    fn test_k256_xchacha_bytes_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes with associated data";
        let associated_data = b"authentication context";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            plaintext,
            associated_data,
            seal_bytes_with_associated_data,
            unseal_bytes_with_associated_data
        );
    }

    #[test]
    fn test_k256_xchacha_elements_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = vec![crate::Felt::new(42), crate::Felt::new(1337), crate::Felt::new(9999)];
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            seal_elements,
            unseal_elements
        );
    }

    #[test]
    fn test_k256_xchacha_elements_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = vec![crate::Felt::new(100), crate::Felt::new(200), crate::Felt::new(300)];
        let associated_data = vec![crate::Felt::new(999), crate::Felt::new(888)];
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            &associated_data,
            seal_elements_with_associated_data,
            unseal_elements_with_associated_data
        );
    }

    #[test]
    fn test_k256_xchacha_invalid_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test invalid associated data";
        let correct_ad = b"correct context";
        let incorrect_ad = b"wrong context";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key
            .seal_bytes_with_associated_data(&mut rng, plaintext, correct_ad)
            .unwrap();
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
        let result = unsealing_key.unseal_bytes_with_associated_data(sealed, incorrect_ad);
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn prop_k256_xchacha_bytes_comprehensive(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
            let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_bytes_with_associated_data, unseal_bytes_with_associated_data);
        }

        #[test]
        fn prop_k256_xchacha_elements_comprehensive(
            plaintext in arbitrary_field_elements(),
            associated_data in arbitrary_field_elements()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
            let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_elements_with_associated_data, unseal_elements_with_associated_data);
        }

        #[test]
        fn prop_k256_xchacha_wrong_key_fails(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty());
            let mut rng = rand::rng();
            let secret1 = SecretKey::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = SecretKey::with_rng(&mut rng);
            let sealing_key = SealingKey::K256XChaCha20Poly1305(public1);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();
            let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret2);
            let result = unsealing_key.unseal_bytes(sealed);
            prop_assert!(result.is_err());
        }
    }
}

/// X25519 + XChaCha20-Poly1305 test suite
mod x25519_xchacha_tests {
    use super::*;

    #[test]
    fn test_x25519_xchacha_bytes_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes encryption";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(sealing_key, unsealing_key, plaintext, seal_bytes, unseal_bytes);
    }

    #[test]
    fn test_x25519_xchacha_bytes_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes with associated data";
        let associated_data = b"authentication context";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            plaintext,
            associated_data,
            seal_bytes_with_associated_data,
            unseal_bytes_with_associated_data
        );
    }

    #[test]
    fn test_x25519_xchacha_elements_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = vec![crate::Felt::new(42), crate::Felt::new(1337), crate::Felt::new(9999)];
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            seal_elements,
            unseal_elements
        );
    }

    #[test]
    fn test_x25519_xchacha_elements_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = vec![crate::Felt::new(100), crate::Felt::new(200), crate::Felt::new(300)];
        let associated_data = vec![crate::Felt::new(999), crate::Felt::new(888)];
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            &associated_data,
            seal_elements_with_associated_data,
            unseal_elements_with_associated_data
        );
    }

    #[test]
    fn test_x25519_xchacha_invalid_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test invalid associated data";
        let correct_ad = b"correct context";
        let incorrect_ad = b"wrong context";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key
            .seal_bytes_with_associated_data(&mut rng, plaintext, correct_ad)
            .unwrap();
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
        let result = unsealing_key.unseal_bytes_with_associated_data(sealed, incorrect_ad);
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn prop_x25519_xchacha_bytes_comprehensive(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey25519::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
            let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_bytes_with_associated_data, unseal_bytes_with_associated_data);
        }

        #[test]
        fn prop_x25519_xchacha_elements_comprehensive(
            plaintext in arbitrary_field_elements(),
            associated_data in arbitrary_field_elements()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey25519::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
            let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_elements_with_associated_data, unseal_elements_with_associated_data);
        }

        #[test]
        fn prop_x25519_xchacha_wrong_key_fails(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty());
            let mut rng = rand::rng();
            let secret1 = SecretKey25519::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = SecretKey25519::with_rng(&mut rng);
            let sealing_key = SealingKey::X25519XChaCha20Poly1305(public1);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();
            let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret2);
            let result = unsealing_key.unseal_bytes(sealed);
            prop_assert!(result.is_err());
        }
    }
}

/// K256 + AeadRpo test suite
mod k256_aead_rpo_tests {
    use super::*;

    // BYTES TESTS
    #[test]
    fn test_k256_aead_rpo_bytes_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes encryption";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256AeadRpo(public_key);
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
        test_basic_roundtrip!(sealing_key, unsealing_key, plaintext, seal_bytes, unseal_bytes);
    }

    #[test]
    fn test_k256_aead_rpo_bytes_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes with associated data";
        let associated_data = b"authentication context";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256AeadRpo(public_key);
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            plaintext,
            associated_data,
            seal_bytes_with_associated_data,
            unseal_bytes_with_associated_data
        );
    }

    #[test]
    fn test_k256_aead_rpo_invalid_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test invalid associated data";
        let correct_ad = b"correct context";
        let incorrect_ad = b"wrong context";
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256AeadRpo(public_key);
        let sealed = sealing_key
            .seal_bytes_with_associated_data(&mut rng, plaintext, correct_ad)
            .unwrap();
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
        let result = unsealing_key.unseal_bytes_with_associated_data(sealed, incorrect_ad);
        assert!(result.is_err());
    }

    // FIELD ELEMENTS TESTS
    #[test]
    fn test_k256_aead_rpo_field_elements_roundtrip() {
        use crate::Felt;
        let mut rng = rand::rng();
        let plaintext = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256AeadRpo(public_key);
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            seal_elements,
            unseal_elements
        );
    }

    #[test]
    fn test_k256_aead_rpo_field_elements_with_associated_data() {
        use crate::Felt;
        let mut rng = rand::rng();
        let plaintext = vec![Felt::new(10), Felt::new(20)];
        let associated_data = vec![Felt::new(100), Felt::new(200)];
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256AeadRpo(public_key);
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            &associated_data,
            seal_elements_with_associated_data,
            unseal_elements_with_associated_data
        );
    }

    proptest! {
        #[test]
        fn prop_k256_aead_rpo_bytes_comprehensive(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::K256AeadRpo(public_key);
            let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_bytes_with_associated_data, unseal_bytes_with_associated_data);
        }

        #[test]
        fn prop_k256_aead_rpo_field_elements_comprehensive(
            plaintext in arbitrary_field_elements(),
            associated_data in arbitrary_field_elements()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::K256AeadRpo(public_key);
            let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_elements_with_associated_data, unseal_elements_with_associated_data);
        }

        #[test]
        fn prop_k256_aead_rpo_wrong_key_fails(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty());
            let mut rng = rand::rng();
            let secret1 = SecretKey::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = SecretKey::with_rng(&mut rng);
            let sealing_key = SealingKey::K256AeadRpo(public1);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();
            let unsealing_key = UnsealingKey::K256AeadRpo(secret2);
            let result = unsealing_key.unseal_bytes(sealed);
            prop_assert!(result.is_err());
        }
    }
}

/// X25519 + AeadRpo test suite
mod x25519_aead_rpo_tests {
    use super::*;

    // BYTES TESTS
    #[test]
    fn test_x25519_aead_rpo_bytes_roundtrip() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes encryption";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        test_basic_roundtrip!(sealing_key, unsealing_key, plaintext, seal_bytes, unseal_bytes);
    }

    #[test]
    fn test_x25519_aead_rpo_bytes_with_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test bytes with associated data";
        let associated_data = b"authentication context";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            plaintext,
            associated_data,
            seal_bytes_with_associated_data,
            unseal_bytes_with_associated_data
        );
    }

    #[test]
    fn test_x25519_aead_rpo_invalid_associated_data() {
        let mut rng = rand::rng();
        let plaintext = b"test invalid associated data";
        let correct_ad = b"correct context";
        let incorrect_ad = b"wrong context";
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let sealed = sealing_key
            .seal_bytes_with_associated_data(&mut rng, plaintext, correct_ad)
            .unwrap();
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        let result = unsealing_key.unseal_bytes_with_associated_data(sealed, incorrect_ad);
        assert!(result.is_err());
    }

    // FIELD ELEMENTS TESTS
    #[test]
    fn test_x25519_aead_rpo_field_elements_roundtrip() {
        use crate::Felt;
        let mut rng = rand::rng();
        let plaintext = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            seal_elements,
            unseal_elements
        );
    }

    #[test]
    fn test_x25519_aead_rpo_field_elements_with_associated_data() {
        use crate::Felt;
        let mut rng = rand::rng();
        let plaintext = vec![Felt::new(10), Felt::new(20)];
        let associated_data = vec![Felt::new(100), Felt::new(200)];
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(public_key);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
        test_basic_roundtrip!(
            sealing_key,
            unsealing_key,
            &plaintext,
            &associated_data,
            seal_elements_with_associated_data,
            unseal_elements_with_associated_data
        );
    }

    proptest! {
        #[test]
        fn prop_x25519_aead_rpo_bytes_comprehensive(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey25519::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::X25519AeadRpo(public_key);
            let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
            test_roundtrip!(sealing_key, unsealing_key, &plaintext, &associated_data, seal_bytes_with_associated_data, unseal_bytes_with_associated_data);
        }

        #[test]
        fn prop_x25519_aead_rpo_field_elements_comprehensive(
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
        fn prop_x25519_aead_rpo_wrong_key_fails(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty());
            let mut rng = rand::rng();
            let secret1 = SecretKey25519::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = SecretKey25519::with_rng(&mut rng);
            let sealing_key = SealingKey::X25519AeadRpo(public1);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();
            let unsealing_key = UnsealingKey::X25519AeadRpo(secret2);
            let result = unsealing_key.unseal_bytes(sealed);
            prop_assert!(result.is_err());
        }
    }
}

// CROSS-SCHEME COMPATIBILITY TESTS
// ================================================================================================
// These tests verify scheme mismatch detection and security properties

/// Tests scheme mismatch detection between different IES variants
mod scheme_compatibility_tests {
    use super::*;

    #[test]
    fn test_scheme_mismatch_k256_xchacha_vs_aead_rpo() {
        let mut rng = rand::rng();
        let plaintext = b"test scheme mismatch";

        // Seal with K256XChaCha20Poly1305
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();

        // Try to unseal with K256AeadRpo (should fail)
        let secret_key2 = SecretKey::with_rng(&mut rng);
        let unsealing_key = UnsealingKey::K256AeadRpo(secret_key2);
        let result = unsealing_key.unseal_bytes(sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_scheme_mismatch_x25519_xchacha_vs_aead_rpo() {
        let mut rng = rand::rng();
        let plaintext = b"test scheme mismatch";

        // Seal with X25519XChaCha20Poly1305
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();

        // Try to unseal with X25519AeadRpo (should fail)
        let secret_key2 = SecretKey25519::with_rng(&mut rng);
        let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key2);
        let result = unsealing_key.unseal_bytes(sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_cross_curve_mismatch_k256_vs_x25519() {
        let mut rng = rand::rng();
        let plaintext = b"test cross-curve mismatch";

        // Seal with K256XChaCha20Poly1305
        let secret_k256 = SecretKey::with_rng(&mut rng);
        let public_k256 = secret_k256.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_k256);
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();

        // Try to unseal with X25519XChaCha20Poly1305 (should fail)
        let secret_x25519 = SecretKey25519::with_rng(&mut rng);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_x25519);
        let result = unsealing_key.unseal_bytes(sealed);
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn prop_general_scheme_mismatch_detection(
            plaintext in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            // Create keys for different schemes
            let secret_k256 = SecretKey::with_rng(&mut rng);
            let public_k256 = secret_k256.public_key();
            let secret_x25519 = SecretKey25519::with_rng(&mut rng);

            // Seal with K256XChaCha20Poly1305
            let sealing_key = SealingKey::K256XChaCha20Poly1305(public_k256);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();

            // Try to unseal with X25519XChaCha20Poly1305 - should fail
            let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_x25519);
            let result = unsealing_key.unseal_bytes(sealed);
            prop_assert!(result.is_err());
        }
    }
}

// PROTOCOL-LEVEL TESTS
// ================================================================================================
// These tests verify protocol-level functionality like serialization and message format

/// Tests for IES protocol-level functionality
mod protocol_tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_serialization_k256() {
        let mut rng = rand::rng();
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_bytes(&mut rng, b"test").unwrap();

        // Extract ephemeral key from sealed message
        let ephemeral_bytes = sealed.ephemeral_key.to_bytes();
        let scheme = sealed.ephemeral_key.scheme();

        // Deserialize and compare
        let reconstructed = EphemeralPublicKey::from_bytes(scheme, &ephemeral_bytes).unwrap();
        assert_eq!(sealed.ephemeral_key, reconstructed);
    }

    #[test]
    fn test_ephemeral_key_serialization_x25519() {
        let mut rng = rand::rng();
        let secret_key = SecretKey25519::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
        let sealed = sealing_key.seal_bytes(&mut rng, b"test").unwrap();

        // Extract ephemeral key from sealed message
        let ephemeral_bytes = sealed.ephemeral_key.to_bytes();
        let scheme = sealed.ephemeral_key.scheme();

        // Deserialize and compare
        let reconstructed = EphemeralPublicKey::from_bytes(scheme, &ephemeral_bytes).unwrap();
        assert_eq!(sealed.ephemeral_key, reconstructed);
    }

    proptest! {
        #[test]
        fn prop_sealed_message_format_consistency(
            plaintext in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
            let sealed = sealing_key.seal_bytes(&mut rng, &plaintext).unwrap();

            // Verify scheme consistency
            let scheme_from_key = sealed.ephemeral_key.scheme();
            let scheme_from_message = sealed.scheme();
            prop_assert_eq!(scheme_from_key, scheme_from_message);

            // Verify scheme name consistency
            prop_assert_eq!(scheme_from_key.name(), sealed.scheme_name());
        }
    }

    // SEALED MESSAGE SERIALIZATION ROUND-TRIP TESTS (BYTES)
    // --------------------------------------------------------------------------------------------

    #[test]
    fn test_sealed_message_serialization_roundtrip_k256_xchacha() {
        let mut rng = rand::rng();
        let sk = crate::dsa::ecdsa_k256_keccak::SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let sealing_key = SealingKey::K256XChaCha20Poly1305(pk);
        let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(sk);

        let plaintext = b"serialization roundtrip";
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();
        let before = sealed.scheme_name();
        let bytes = sealed.to_bytes();
        let sealed2 =
            <SealedMessage as crate::utils::Deserializable>::read_from_bytes(&bytes).unwrap();
        let after = sealed2.scheme_name();
        assert_eq!(before, after);
        let opened = unsealing_key.unseal_bytes(sealed2).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_sealed_message_serialization_roundtrip_x25519_xchacha() {
        let mut rng = rand::rng();
        let sk = crate::dsa::eddsa_25519::SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let sealing_key = SealingKey::X25519XChaCha20Poly1305(pk);
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(sk);

        let plaintext = b"serialization roundtrip";
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();
        let before = sealed.scheme_name();
        let bytes = sealed.to_bytes();
        let sealed2 =
            <SealedMessage as crate::utils::Deserializable>::read_from_bytes(&bytes).unwrap();
        let after = sealed2.scheme_name();
        assert_eq!(before, after);
        let opened = unsealing_key.unseal_bytes(sealed2).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_sealed_message_serialization_roundtrip_k256_aeadrpo() {
        let mut rng = rand::rng();
        let sk = crate::dsa::ecdsa_k256_keccak::SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let sealing_key = SealingKey::K256AeadRpo(pk);
        let unsealing_key = UnsealingKey::K256AeadRpo(sk);

        let plaintext = b"serialization roundtrip";
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();
        let before = sealed.scheme_name();
        let bytes = sealed.to_bytes();
        let sealed2 =
            <SealedMessage as crate::utils::Deserializable>::read_from_bytes(&bytes).unwrap();
        let after = sealed2.scheme_name();
        assert_eq!(before, after);
        let opened = unsealing_key.unseal_bytes(sealed2).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_sealed_message_serialization_roundtrip_x25519_aeadrpo() {
        let mut rng = rand::rng();
        let sk = crate::dsa::eddsa_25519::SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let sealing_key = SealingKey::X25519AeadRpo(pk);
        let unsealing_key = UnsealingKey::X25519AeadRpo(sk);

        let plaintext = b"serialization roundtrip";
        let sealed = sealing_key.seal_bytes(&mut rng, plaintext).unwrap();
        let before = sealed.scheme_name();
        let bytes = sealed.to_bytes();
        let sealed2 =
            <SealedMessage as crate::utils::Deserializable>::read_from_bytes(&bytes).unwrap();
        let after = sealed2.scheme_name();
        assert_eq!(before, after);
        let opened = unsealing_key.unseal_bytes(sealed2).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }
}

// INTEGRATION AND REGRESSION TESTS
// ================================================================================================
// Tests for edge cases, integration scenarios, and regression prevention

/// Integration and regression tests
mod integration_tests {
    use super::*;

    proptest! {
        #[test]
        fn prop_field_elements_consistency(
            field_values in prop::collection::vec(any::<u64>(), 1..10)
        ) {
            use crate::Felt;
            let mut rng = rand::rng();
            let secret_key = SecretKey25519::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let sealing_key = SealingKey::X25519AeadRpo(public_key);
            let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);

            // Test field elements encryption
            let field_elements: Vec<Felt> = field_values.iter().map(|&v| Felt::new(v)).collect();
            let sealed_elements = sealing_key.seal_elements(&mut rng, &field_elements).unwrap();
            let decrypted_elements = unsealing_key.unseal_elements(sealed_elements).unwrap();
            prop_assert_eq!(field_elements.clone(), decrypted_elements);

            // Test with empty associated data
            let field_elements_clone = field_elements.clone();
            let sealed_with_empty_ad = sealing_key.seal_elements_with_associated_data(&mut rng, &field_elements_clone, &Vec::<Felt>::new()).unwrap();
            let decrypted_with_empty_ad = unsealing_key.unseal_elements_with_associated_data(sealed_with_empty_ad, &Vec::<Felt>::new()).unwrap();
            prop_assert_eq!(field_elements, decrypted_with_empty_ad);
        }

        #[test]
        fn prop_different_keys_produce_different_ciphertexts(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty());
            let mut rng = rand::rng();

            // Create two different key pairs
            let secret1 = SecretKey::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = SecretKey::with_rng(&mut rng);
            let public2 = secret2.public_key();

            let sealing_key1 = SealingKey::K256AeadRpo(public1);
            let sealing_key2 = SealingKey::K256AeadRpo(public2);

            let sealed1 = sealing_key1.seal_bytes(&mut rng, &plaintext).unwrap();
            let sealed2 = sealing_key2.seal_bytes(&mut rng, &plaintext).unwrap();

            // Different keys should produce different ciphertexts
            prop_assert_ne!(sealed1.ciphertext, sealed2.ciphertext);
        }
    }
}
