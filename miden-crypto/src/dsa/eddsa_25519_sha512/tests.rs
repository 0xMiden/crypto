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

/// Encode R and S (little-endian 32-byte arrays) into DER SEQUENCE { INTEGER, INTEGER }.
fn encode_der(r_le: &[u8; 32], s_le: &[u8; 32]) -> Vec<u8> {
    fn le_to_der_integer(le: &[u8; 32]) -> Vec<u8> {
        let mut be = *le;
        be.reverse();
        // Strip leading zeros (but keep at least one byte).
        let start = be.iter().position(|&b| b != 0).unwrap_or(31);
        let stripped = &be[start..];
        let needs_pad = stripped[0] & 0x80 != 0;
        let len = stripped.len() + usize::from(needs_pad);
        let mut out = Vec::with_capacity(2 + len);
        out.push(0x02); // INTEGER tag
        out.push(len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(stripped);
        out
    }
    let r_der = le_to_der_integer(r_le);
    let s_der = le_to_der_integer(s_le);
    let seq_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(2 + seq_len);
    out.push(0x30); // SEQUENCE tag
    out.push(seq_len as u8);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

#[test]
fn from_der_roundtrip() {
    let mut rng = seeded_rng([10u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();

    let msg = Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let sig = sk.sign(msg);

    // Encode signature to DER
    let sig_bytes = sig.inner.to_bytes();
    let r: [u8; 32] = sig_bytes[..32].try_into().unwrap();
    let s: [u8; 32] = sig_bytes[32..].try_into().unwrap();
    let der = encode_der(&r, &s);

    // Decode and verify
    let recovered = Signature::from_der(&der).expect("valid DER should parse");
    assert_eq!(recovered, sig);
    assert!(pk.verify(msg, &recovered));
}

#[test]
fn from_der_rejects_bad_sequence_tag() {
    // A valid-length blob but with wrong outer tag (0x31 instead of 0x30)
    let mut der = encode_der(&[0u8; 32], &[0u8; 32]);
    der[0] = 0x31;
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_trailing_data() {
    let mut der = encode_der(&[0u8; 32], &[0u8; 32]);
    der.push(0x00); // extra byte after SEQUENCE
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_empty_input() {
    assert!(Signature::from_der(&[]).is_err());
}

#[test]
fn from_der_rejects_truncated_integer() {
    // Craft a SEQUENCE whose declared length extends beyond the actual data.
    let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01]; // S integer body missing
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_long_form_length() {
    // Valid content but using BER-style long-form length 0x81 0x44 instead of
    // short-form 0x44. DER requires shortest form, and Ed25519 blobs always fit
    // in short-form.
    let inner = encode_der(&[1u8; 32], &[2u8; 32]);
    // Replace outer SEQUENCE: swap short-form len with long-form
    let seq_body = &inner[2..]; // skip tag + original 1-byte length
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE tag
    der.push(0x81); // long-form: 1 subsequent length byte
    der.push(seq_body.len() as u8);
    der.extend_from_slice(seq_body);
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_non_canonical_integer_padding() {
    // An INTEGER with an unnecessary leading 0x00 byte: the next byte's high bit
    // is clear, so the 0x00 is superfluous and violates X.690 section 8.3.2.
    // R = 0x00 0x01 (non-canonical: should just be 0x01)
    let r_int = [0x02, 0x02, 0x00, 0x01]; // INTEGER tag, len=2, body=00 01
    let s_int = [0x02, 0x01, 0x01]; // INTEGER tag, len=1, body=01
    let seq_len = (r_int.len() + s_int.len()) as u8;
    let mut der = Vec::new();
    der.push(0x30);
    der.push(seq_len);
    der.extend_from_slice(&r_int);
    der.extend_from_slice(&s_int);
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_empty_integer() {
    // An INTEGER with zero-length content is invalid per DER.
    let r_int = [0x02, 0x00]; // INTEGER tag, len=0
    let s_int = [0x02, 0x01, 0x01];
    let seq_len = (r_int.len() + s_int.len()) as u8;
    let mut der = Vec::new();
    der.push(0x30);
    der.push(seq_len);
    der.extend_from_slice(&r_int);
    der.extend_from_slice(&s_int);
    assert!(Signature::from_der(&der).is_err());
}

#[test]
fn from_der_rejects_negative_integer() {
    // An INTEGER whose first byte has the high bit set (negative in two's
    // complement) is invalid for an Ed25519 signature component.
    let r_int = [0x02, 0x01, 0x80]; // INTEGER tag, len=1, body=0x80 (negative)
    let s_int = [0x02, 0x01, 0x01];
    let seq_len = (r_int.len() + s_int.len()) as u8;
    let mut der = Vec::new();
    der.push(0x30);
    der.push(seq_len);
    der.extend_from_slice(&r_int);
    der.extend_from_slice(&s_int);
    assert!(Signature::from_der(&der).is_err());
}
