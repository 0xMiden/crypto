use proptest::{
    prelude::{any, prop},
    prop_assert_eq, prop_assert_ne, prop_assume, proptest,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;

// PROPERTY-BASED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn test_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 1usize..100,
        data_len in 1usize..100,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random field elements
        let associated_data: Vec<Felt> = (0..associated_data_len)
            .map(|_| Felt::new(rng.next_u64()))
            .collect();
        let data: Vec<Felt> = (0..data_len)
            .map(|_| Felt::new(rng.next_u64()))
            .collect();

        let encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);
        let decrypted = key.decrypt(&encrypted).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_bytes_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 0usize..1000,
        data_len in 0usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random bytes
        let mut associated_data = vec![0_u8; associated_data_len];
        rng.fill_bytes(&mut associated_data);

        let mut data = vec![0_u8; data_len];
        rng.fill_bytes(&mut data);


        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce);
        let decrypted = key.decrypt_bytes(&encrypted).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_different_keys_different_outputs(
        seed1 in any::<u64>(),
        seed2 in any::<u64>(),
        associated_data in prop::collection::vec(any::<u64>(), 1..500),
        data in prop::collection::vec(any::<u64>(), 1..500),
    ) {
        prop_assume!(seed1 != seed2);

        let mut rng1 = ChaCha20Rng::seed_from_u64(seed1);
        let mut rng2 = ChaCha20Rng::seed_from_u64(seed2);

        let key1 = SecretKey::with_rng(&mut rng1);
        let key2 = SecretKey::with_rng(&mut rng2);
        let nonce_word = [ONE; 4];
        let nonce1 = Nonce::from_word(nonce_word.into());
        let nonce2 = Nonce::from_word(nonce_word.into());

        let associated_data: Vec<Felt> = associated_data.into_iter()
            .map(|x| Felt::new(x))
            .collect();
        let data: Vec<Felt> = data.into_iter()
            .map(|x| Felt::new(x))
            .collect();

        let encrypted1 = key1.encrypt_with_nonce(&data, &associated_data, nonce1);
        let encrypted2 = key2.encrypt_with_nonce(&data, &associated_data, nonce2);

        // Different keys should produce different ciphertexts
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        prop_assert_ne!(encrypted1.auth_tag, encrypted2.auth_tag);
    }

    #[test]
    fn test_different_nonces_different_outputs(
        seed in any::<u64>(),
        associated_data in prop::collection::vec(any::<u64>(), 1..50),
        data in prop::collection::vec(any::<u64>(), 1..50),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce1 = Nonce::from_word([ZERO; 4].into());
        let nonce2 = Nonce::from_word([ONE; 4].into());

        let associated_data: Vec<Felt> = associated_data.into_iter()
            .map(|x| Felt::new(x ))
            .collect();
        let data: Vec<Felt> = data.into_iter()
            .map(|x| Felt::new(x ))
            .collect();

        let encrypted1 = key.encrypt_with_nonce(&data,&associated_data, nonce1);
        let encrypted2 = key.encrypt_with_nonce(&data, &associated_data, nonce2);

        // Different nonces should produce different ciphertexts (with very high probability)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        prop_assert_ne!(encrypted1.auth_tag, encrypted2.auth_tag);
    }
}

// UNIT TESTS
// ================================================================================================

#[test]
fn test_secret_key_creation() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key1 = SecretKey::with_rng(&mut rng);
    let key2 = SecretKey::with_rng(&mut rng);

    // Keys should be different
    assert_ne!(key1, key2);
}

#[test]
fn test_nonce_creation() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let nonce1 = Nonce::with_rng(&mut rng);
    let nonce2 = Nonce::with_rng(&mut rng);

    // Nonces should be different
    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_empty_data_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let empty_data: Vec<Felt> = vec![];
    let encrypted = key.encrypt_with_nonce(&empty_data, &associated_data, nonce);
    let decrypted = key.decrypt(&encrypted).unwrap();

    assert_eq!(empty_data, decrypted);
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_single_element_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new(42)];
    let encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);
    let decrypted = key.decrypt(&encrypted).unwrap();

    assert_eq!(data, decrypted);
    assert_eq!(encrypted.ciphertext.len(), 8);
}

#[test]
fn test_large_data_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    // Test with data larger than rate
    let data: Vec<Felt> = (0..100).map(|i| Felt::new(i as u64)).collect();

    let encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);
    let decrypted = key.decrypt(&encrypted).unwrap();

    assert_eq!(data, decrypted);
}

#[test]
fn test_encryption_various_lengths() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let associated_data: Vec<Felt> = vec![ONE; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 1000] {
        let data: Vec<Felt> = (0..len).map(|i| Felt::new(i as u64)).collect();

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(data, decrypted, "Failed for length {}", len);
    }
}

#[test]
fn test_bytes_encryption_various_lengths() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let associated_data: Vec<u8> = vec![1; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 1000] {
        let mut data = vec![0_u8; len];
        rng.fill_bytes(&mut data);

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce);
        let decrypted = key.decrypt_bytes(&encrypted).unwrap();

        assert_eq!(data, decrypted, "Failed for length {}", len);
    }
}

#[test]
fn test_ciphertext_tampering_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new(123), Felt::new(456)];
    let mut encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);

    // Tamper with ciphertext
    encrypted.ciphertext[0] += ONE;

    let result = key.decrypt(&encrypted);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_auth_tag_tampering_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new(123), Felt::new(456)];
    let mut encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce);

    // Tamper with auth tag
    let mut tampered_tag = encrypted.auth_tag.0;
    tampered_tag[0] += ONE;
    encrypted.auth_tag = AuthTag(tampered_tag);

    let result = key.decrypt(&encrypted);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_wrong_key_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key1 = SecretKey::with_rng(&mut rng);
    let key2 = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new(123), Felt::new(456)];
    let encrypted = key1.encrypt_with_nonce(&data, &associated_data, nonce);

    // Try to decrypt with wrong key
    let result = key2.decrypt(&encrypted);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_wrong_nonce_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce1 = Nonce::with_rng(&mut rng);
    let nonce2 = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new(123), Felt::new(456)];
    let mut encrypted = key.encrypt_with_nonce(&data, &associated_data, nonce1);

    // Try to decrypt with wrong nonce
    encrypted.nonce = nonce2;
    let result = key.decrypt(&encrypted);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

// SECURITY TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod security_tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_key_uniqueness() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut keys = HashSet::new();

        // Generate 1000 keys and ensure they're all unique
        for _ in 0..1000 {
            let key = SecretKey::with_rng(&mut rng);
            let key_bytes = format!("{:?}", key.0);
            assert!(keys.insert(key_bytes), "Duplicate key generated!");
        }
    }

    #[test]
    fn test_nonce_uniqueness() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut nonces = HashSet::new();

        // Generate 1000 nonces and ensure they're all unique
        for _ in 0..1000 {
            let nonce = Nonce::with_rng(&mut rng);
            let nonce_bytes = format!("{:?}", nonce.0);
            assert!(nonces.insert(nonce_bytes), "Duplicate nonce generated!");
        }
    }

    #[test]
    fn test_ciphertext_appears_random() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = SecretKey::with_rng(&mut rng);

        // Encrypt the same plaintext with different nonces
        let associated_data: Vec<Felt> = vec![ONE; 8];
        let plaintext = vec![ZERO; 10]; // All zeros
        let mut ciphertexts = Vec::new();

        for _ in 0..100 {
            let nonce = Nonce::with_rng(&mut rng);
            let encrypted = key.encrypt_with_nonce(&plaintext, &associated_data, nonce);
            ciphertexts.push(encrypted.ciphertext);
        }

        // Ensure all ciphertexts are different (randomness test)
        for i in 0..ciphertexts.len() {
            for j in i + 1..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Ciphertexts {} and {} are identical!",
                    i, j
                );
            }
        }
    }
}
