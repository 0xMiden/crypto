use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::dsa::falcon512_rpo::{SecretKey, Serializable};

mod data;

#[test]
fn test_secret_key_debug_redaction() {
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let sk = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{sk:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{sk}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}

#[test]
fn test_signature_determinism() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let sk = SecretKey::with_rng(&mut rng);
    let message = b"data";

    // Sign the same message twice
    let signature1 = sk.sign(message.into());
    let signature2 = sk.sign(message.into());

    // Signatures should be identical (deterministic)
    let serialized = signature1.to_bytes();
    assert_eq!(serialized, signature2.to_bytes());

    // Compare against known test vector for cross-platform determinism
    assert_eq!(serialized, data::DETERMINISTIC_SIGNATURE);

    // Also verify the signature is valid
    let pk = sk.public_key();
    assert!(pk.verify(message.into(), &signature1));
}

/// Tests that sign_shake256 produces signatures verifiable by fn-dsa-vrfy.
///
/// This test verifies end-to-end compatibility with fn-dsa by:
/// 1. Creating a secret key
/// 2. Signing a message using sign_shake256 (SHAKE256 hash-to-point)
/// 3. Encoding the signature in fn-dsa's format
/// 4. Verifying with fn-dsa-vrfy's verification code
#[test]
fn test_sign_shake256_verified_by_fn_dsa() {
    use fn_dsa_comm::{codec::comp_encode, signature_size};
    use fn_dsa_vrfy::{DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON, VerifyingKey, VerifyingKey512};

    const LOGN: u32 = 9;

    // Create a deterministic RNG for reproducibility
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Generate a secret key
    let sk = SecretKey::with_rng(&mut rng);

    // Get the public key in fn-dsa's format
    let pk = sk.public_key();
    let pk_bytes = (&pk).to_bytes();

    // Decode the public key using fn-dsa-vrfy
    let vk = VerifyingKey512::decode(&pk_bytes).expect("Failed to decode public key");

    // Sign a message using SHAKE256 hash-to-point
    let message = b"test message for fn-dsa compatibility";
    let (nonce, s2) = sk.sign_shake256(message, &mut rng);

    // Encode the signature in fn-dsa's format:
    // sig[0] = 0x30 + logn (header)
    // sig[1..41] = nonce (40 bytes)
    // sig[41..] = compressed s2
    // The signature must be exactly signature_size(logn) = 666 bytes for Falcon-512
    let sig_len = signature_size(LOGN);
    let mut sig = vec![0u8; sig_len];
    sig[0] = 0x30 + (LOGN as u8);
    sig[1..41].copy_from_slice(&nonce);

    // Compress s2 into the signature
    let compressed = comp_encode(&s2, &mut sig[41..]);
    assert!(compressed, "Signature encoding failed");

    // Verify the signature using fn-dsa-vrfy
    let verified = vk.verify(&sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, message);
    assert!(verified, "Signature verification failed");

    // Verify that a modified message fails verification
    let bad_message = b"different message";
    let bad_verified = vk.verify(&sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, bad_message);
    assert!(!bad_verified, "Verification should fail for wrong message");
}
