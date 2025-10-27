use super::*;

#[test]
fn sign_and_verify_roundtrip() {
    use rand::rng;

    let mut rng = rng();
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    let msg = Word::default(); // all zeros
    let sig = sk.sign(msg);

    assert!(pk.verify(msg, &sig));
}

#[test]
fn test_key_generation_serialization() {
    let mut rng = rand::rng();

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
    let mut rng = rand::rng();
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
    let mut rng = rand::rng();
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

        // Verify using verify_with_k should give the same result as verify()
        let result_with_k = pk.verify_with_k(k_hash, &signature);
        let result_standard = pk.verify(message, &signature);

        assert_eq!(
            result_with_k, result_standard,
            "verify_with_k(compute_challenge_k(...)) should equal verify()"
        );
        assert!(result_standard, "Signature should be valid");

        // Test with wrong message - both should fail
        let wrong_message =
            Word::from([Felt::new(999), Felt::new(888), Felt::new(777), Felt::new(666)]);
        let wrong_k_hash = pk.compute_challenge_k(wrong_message, &signature);

        assert!(
            !pk.verify_with_k(wrong_k_hash, &signature),
            "verify_with_k with wrong hash should fail"
        );
        assert!(!pk.verify(wrong_message, &signature), "verify with wrong message should fail");
    }
}
