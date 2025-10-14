use rand::rng;

use super::*;
use crate::Felt;

#[test]
fn test_key_generation() {
    let mut rng = rng();

    let secret_key = SecretKey::with_rng(&mut rng);
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
fn test_public_key_recovery() {
    let mut rng = rng();

    let mut secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Generate a signature using the secret key
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message);

    // Recover the public key
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
    assert_eq!(public_key, recovered_pk);

    // Using the wrong message, we shouldn't be able to recover the public key
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(5)].into();
    let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
    assert!(public_key != recovered_pk);
}

#[test]
fn test_sign_and_verify() {
    let mut rng = rng();

    let mut secret_key = SecretKey::with_rng(&mut rng);
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
fn test_signature_serialization_default() {
    let mut rng = rng();

    let mut secret_key = SecretKey::with_rng(&mut rng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message);

    let sig_bytes = signature.to_bytes();
    let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

    assert_eq!(signature, recovered_sig);
}

#[test]
fn test_signature_serialization() {
    let mut rng = rng();

    let mut secret_key = SecretKey::with_rng(&mut rng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message);
    let recovery_id = signature.v();

    let sig_bytes = signature.to_sec1_bytes();
    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();

    assert_eq!(signature, recovered_sig);

    let recovery_id = (recovery_id + 1) % 4;
    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);

    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);
}

#[test]
fn test_secret_key_debug_redaction() {
    let mut rng = rng();
    let secret_key = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{secret_key:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{secret_key}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}
