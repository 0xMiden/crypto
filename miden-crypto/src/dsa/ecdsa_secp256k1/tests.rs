
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
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
    assert_eq!(public_key, recovered_pk);

    // Using the wrong message, we shouldn't be able to recover the public key
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(5)].into();
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
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
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
    assert_eq!(public_key, recovered_pk);

    // Using the wrong message, we shouldn't be able to recover the public key
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(5)].into();
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
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
fn test_signature_serialization_default_sha256() {
    let mut secret_key = SecretKey::with_rng(&mut OsRng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message, EcdsaHasher::Sha256);

    let sig_bytes = signature.to_bytes();
    let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

    assert_eq!(signature, recovered_sig);
}

#[test]
fn test_signature_serialization_default_keccak() {
    let mut secret_key = SecretKey::with_rng(&mut OsRng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message, EcdsaHasher::Keccak);

    let sig_bytes = signature.to_bytes();
    let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

    assert_eq!(signature, recovered_sig);
}

#[test]
fn test_signature_serialization_sec1_sha256() {
    let mut secret_key = SecretKey::with_rng(&mut OsRng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message, EcdsaHasher::Sha256);
    let recovery_id = signature.v();

    let sig_bytes = signature.to_sec1_bytes();
    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Sha256, recovery_id).unwrap();

    assert_eq!(signature, recovered_sig);

    let recovery_id = (recovery_id + 1) % 4;
    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Sha256, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);

    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Keccak, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);
}

#[test]
fn test_signature_serialization_keccak() {
    let mut secret_key = SecretKey::with_rng(&mut OsRng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message, EcdsaHasher::Keccak);
    let recovery_id = signature.v();

    let sig_bytes = signature.to_sec1_bytes();
    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Keccak, recovery_id).unwrap();

    assert_eq!(signature, recovered_sig);

    let recovery_id = (recovery_id + 1) % 4;
    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Keccak, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);

    let recovered_sig =
        Signature::from_sec1_bytes_and_hasher(sig_bytes, EcdsaHasher::Sha256, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);
}
