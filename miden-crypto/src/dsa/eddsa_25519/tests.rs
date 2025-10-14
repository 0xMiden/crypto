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
    let serialized_sk = SecretKey::read_from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk.to_bytes(), serialized_sk.to_bytes());

    // Public key -> bytes -> recovered public key
    let pk_bytes = pk.to_bytes();
    let serialized_pk = PublicKey::read_from_bytes(&pk_bytes).unwrap();
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
