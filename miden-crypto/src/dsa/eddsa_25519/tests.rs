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
fn derived_trait_consistency() {
    let mut rng = rand::rng();

    let sk = SecretKey::with_rng(&mut rng);
    let sk_clone = sk.clone();
    assert_eq!(sk.to_bytes(), sk_clone.to_bytes());
    assert_eq!(format!("{sk:?}"), format!("{sk_clone:?}"));

    let pk = sk.public_key();
    let pk_clone = pk.clone();
    assert_eq!(pk, pk_clone);
    assert_eq!(format!("{pk:?}"), format!("{pk_clone:?}"));

    let msg = Word::from([Felt::new(3), Felt::new(2), Felt::new(1), Felt::new(0)]);
    let sig = sk.sign(msg);
    let sig_clone = sig.clone();
    assert_eq!(sig, sig_clone);
    assert_eq!(format!("{sig:?}"), format!("{sig_clone:?}"));
}
