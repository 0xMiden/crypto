use super::*;
use crate::rand::test_utils::seeded_rng;

#[test]
fn sign_and_verify_roundtrip() {
    let mut rng = seeded_rng([0u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    let msg = Word::default(); // all zeros
    let sig = sk.sign(msg);

    assert!(pk.verify(msg, &sig));
}

#[test]
fn test_key_generation_serialization() {
    let mut rng = seeded_rng([1u8; 32]);

    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    // Secret key -> bytes -> recovered secret key
    let sk_bytes = sk.to_bytes();
    let serialized_sk = SecretKey::read_from_bytes(&sk_bytes)
        .expect("deserialization of valid secret key bytes should succeed");
    assert_eq!(sk.to_bytes(), serialized_sk.to_bytes());

    // Public key -> bytes -> recovered public key
    let pk_bytes = pk.to_bytes();
    let serialized_pk = PublicKey::read_from_bytes(&pk_bytes)
        .expect("deserialization of valid public key bytes should succeed");
    assert_eq!(pk, serialized_pk);
}

#[test]
fn test_secret_key_debug_redaction() {
    let mut rng = seeded_rng([2u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{sk:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{sk}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}

#[test]
fn test_compute_challenge_k_equivalence() {
    let mut rng = seeded_rng([3u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    // Test with multiple different messages
    let messages = [
        Word::default(),
        Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
        Word::from([Felt::new(42), Felt::new(100), Felt::new(255), Felt::new(1000)]),
    ];

    for message in messages {
        let signature = sk.sign(message);

        // Compute the challenge hash using the helper method
        let k_hash = pk.compute_challenge_k(message, &signature);

        // Verify using verify_with_unchecked_k should give the same result as verify()
        let result_with_k = pk.verify_with_unchecked_k(k_hash, &signature).is_ok();
        let result_standard = pk.verify(message, &signature);

        assert_eq!(
            result_with_k, result_standard,
            "verify_with_unchecked_k(compute_challenge_k(...)) should equal verify()"
        );
        assert!(result_standard, "Signature should be valid");

        // Test with wrong message - both should fail
        let wrong_message =
            Word::from([Felt::new(999), Felt::new(888), Felt::new(777), Felt::new(666)]);
        let wrong_k_hash = pk.compute_challenge_k(wrong_message, &signature);

        assert!(matches!(
            pk.verify_with_unchecked_k(wrong_k_hash, &signature),
            Err(UncheckedVerificationError::EquationMismatch)
        ));
        assert!(!pk.verify(wrong_message, &signature), "verify with wrong message should fail");
    }
}

// DER tests
// ================================================================================================

/// Wrap a raw 64-byte Ed25519 signature in a DER BIT STRING.
fn encode_bitstring(sig_bytes: &[u8; 64]) -> Vec<u8> {
    // BIT STRING tag (0x03), length (65 = 1 unused-bits byte + 64 sig bytes),
    // unused bits (0x00), then the raw signature.
    let mut out = Vec::with_capacity(2 + 1 + 64);
    out.push(0x03); // BIT STRING tag
    out.push(65); // length: 1 + 64
    out.push(0x00); // unused bits
    out.extend_from_slice(sig_bytes);
    out
}

#[test]
fn from_der_bitstring_roundtrip() {
    let mut rng = seeded_rng([10u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    let msg = Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let sig = sk.sign(msg);

    // Encode the signature as DER BIT STRING (standard encoding per RFC 8410)
    let sig_bytes = sig.inner.to_bytes();
    let der = encode_bitstring(&sig_bytes);

    // Decode and verify
    let recovered = Signature::from_der(&der).expect("valid DER BIT STRING should parse");
    assert_eq!(recovered, sig);
    assert!(pk.verify(msg, &recovered));
}

#[test]
fn from_der_raw_64_bytes() {
    let mut rng = seeded_rng([11u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    let msg = Word::from([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
    let sig = sk.sign(msg);

    // Pass raw 64 bytes directly (RFC 8032 native format)
    let sig_bytes = sig.inner.to_bytes();
    let recovered =
        Signature::from_der(&sig_bytes).expect("raw 64-byte signature should parse");
    assert_eq!(recovered, sig);
    assert!(pk.verify(msg, &recovered));
}

#[test]
fn from_der_rejects_bad_tag() {
    // Use SEQUENCE tag (0x30) instead of BIT STRING (0x03)
    let mut der = encode_bitstring(&[0u8; 64]);
    der[0] = 0x30;
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_trailing_data() {
    let mut der = encode_bitstring(&[0u8; 64]);
    der.push(0x00); // extra byte after BIT STRING
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_empty_input() {
    assert!(Signature::from_der(&[]).is_err());
}

#[test]
fn from_der_rejects_nonzero_unused_bits() {
    let mut der = encode_bitstring(&[0u8; 64]);
    der[2] = 0x01; // unused-bits byte should be 0
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_wrong_length() {
    // BIT STRING with only 32 bytes of signature (too short)
    let short_sig = [0u8; 32];
    let mut der = Vec::new();
    der.push(0x03); // BIT STRING tag
    der.push(33); // length: 1 + 32
    der.push(0x00); // unused bits
    der.extend_from_slice(&short_sig);
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_long_form_length() {
    let sig_bytes = [1u8; 64];
    // Use BER-style long-form length 0x81 0x41 instead of short-form 0x41.
    let mut der = Vec::new();
    der.push(0x03); // BIT STRING tag
    der.push(0x81); // long-form: 1 subsequent length byte
    der.push(65); // actual length
    der.push(0x00); // unused bits
    der.extend_from_slice(&sig_bytes);
    assert!(Signature::from_der(&der).is_err());
}
