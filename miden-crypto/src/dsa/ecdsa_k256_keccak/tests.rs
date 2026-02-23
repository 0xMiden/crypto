use super::*;
use crate::{Felt, rand::test_utils::seeded_rng};

#[test]
fn test_key_generation() {
    let mut rng = seeded_rng([0u8; 32]);

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
    let mut rng = seeded_rng([1u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
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
    let mut rng = seeded_rng([2u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
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
    let mut rng = seeded_rng([3u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
    let message = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let signature = secret_key.sign(message);

    let sig_bytes = signature.to_bytes();
    let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

    assert_eq!(signature, recovered_sig);
}

#[test]
fn test_signature_serialization() {
    let mut rng = seeded_rng([4u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
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
    let mut rng = seeded_rng([5u8; 32]);
    let secret_key = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{secret_key:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{secret_key}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}

#[cfg(feature = "std")]
#[test]
fn test_signature_serde() {
    use crate::utils::SliceReader;
    let sig0 = SecretKey::new().sign(Word::from([5, 0, 0, 0u32]));
    let sig_bytes = sig0.to_bytes();
    let mut slice_reader = SliceReader::new(&sig_bytes);
    let sig0_deserialized = Signature::read_from(&mut slice_reader).unwrap();

    assert!(!slice_reader.has_more_bytes());
    assert_eq!(sig0, sig0_deserialized);
}

#[test]
fn test_signature_from_der_success() {
    // DER-encoded form of an ASN.1 SEQUENCE containing two INTEGER values.
    let der: [u8; 8] = [
        0x30, 0x06, // Sequence tag and length of sequence contents.
        0x02, 0x01, 0x01, // Integer 1.
        0x02, 0x01, 0x09, // Integer 2.
    ];
    let v = 2u8;

    let sig = Signature::from_der(&der, v).expect("from_der should parse valid DER");

    // Expect r = 1 and s = 9 in 32-byte big-endian form.
    let mut expected_r = [0u8; 32];
    expected_r[31] = 1;
    let mut expected_s = [0u8; 32];
    expected_s[31] = 9;

    assert_eq!(sig.r(), &expected_r);
    assert_eq!(sig.s(), &expected_s);
    assert_eq!(sig.v(), v);
}

#[test]
fn test_signature_from_der_recovery_id_variation() {
    // DER encoding with two integers both equal to 1.
    let der: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

    let sig_v0 = Signature::from_der(&der, 0).unwrap();
    let sig_v3 = Signature::from_der(&der, 3).unwrap();

    // r and s must be identical; v differs, so signatures should not be equal.
    assert_eq!(sig_v0.r(), sig_v3.r());
    assert_eq!(sig_v0.s(), sig_v3.s());
    assert_ne!(sig_v0.v(), sig_v3.v());
    assert_ne!(sig_v0, sig_v3);
}

#[test]
fn test_signature_from_der_invalid() {
    // Empty input should fail at DER parsing stage (der error).
    match Signature::from_der(&[], 0) {
        Err(SignatureError::DerError(_)) => {},
        other => panic!("expected DerError for empty DER, got {:?}", other),
    }

    // Malformed/truncated DER should also fail.
    let der_bad: [u8; 2] = [0x30, 0x01];
    match Signature::from_der(&der_bad, 0) {
        Err(SignatureError::DerError(_)) => {},
        other => panic!("expected DerError for malformed DER, got {:?}", other),
    }
}
