use data::DETERMINISTIC_SIGNATURE;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::dsa::falcon512_rpo::{PREVERSIONED_NONCE, PREVERSIONED_NONCE_LEN, SecretKey, Serializable};

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
    let signature = sk.sign(message.into());
    let serialized_signature = signature.to_bytes();

    assert_eq!(serialized_signature, DETERMINISTIC_SIGNATURE);
}

#[test]
fn check_preversioned_fixed_nonce() {
    assert_eq!(build_preversioned_fixed_nonce(), PREVERSIONED_NONCE)
}

/// Builds the preversioned portion of the fixed nonce following [1].
///
/// Note that [1] uses the term salt instead of nonce.
///
/// [1]: https://github.com/algorand/falcon/blob/main/falcon-det.pdf
fn build_preversioned_fixed_nonce() -> [u8; PREVERSIONED_NONCE_LEN] {
    use crate::dsa::falcon512_rpo::LOG_N;

    let mut result = [0_u8; 39];
    result[0] = LOG_N;
    let domain_separator = "RPO-FALCON-DET".as_bytes();

    result
        .iter_mut()
        .skip(1)
        .zip(domain_separator.iter())
        .for_each(|(dst, src)| *dst = *src);

    result
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

/// End-to-end test against fn-dsa C reference implementation KAT vectors.
///
/// This test verifies the complete signing flow by:
/// 1. Constructing a SecretKey from the KAT basis polynomials (f, g, F, G)
/// 2. Verifying the derived public key matches the KAT verification key
/// 3. Signing with the KAT nonce and seed using sign_shake256_inner
/// 4. Verifying the signature matches the expected KAT signature
#[test]
fn test_end_to_end_against_c_reference_kat() {
    use crate::dsa::falcon512_rpo::{N, SecretKey, math::Polynomial};
    use data::{
        FN_DSA_KAT_512_BIG_F, FN_DSA_KAT_512_BIG_G, FN_DSA_KAT_512_F, FN_DSA_KAT_512_G,
        FN_DSA_KAT_512_RND, FN_DSA_KAT_512_SIG_RAW, FN_DSA_KAT_512_VK,
    };
    use fn_dsa_sign::tests::ChaCha20PRNG;

    // Build the short lattice basis [g, f, G, F] from KAT data
    let basis = [
        Polynomial::new(FN_DSA_KAT_512_G.iter().map(|&c| c).collect()),  // g
        Polynomial::new(FN_DSA_KAT_512_F.iter().map(|&c| c).collect()),  // f
        Polynomial::new(FN_DSA_KAT_512_BIG_G.iter().map(|&c| c).collect()), // G
        Polynomial::new(FN_DSA_KAT_512_BIG_F.iter().map(|&c| c).collect()), // F
    ];

    // Construct SecretKey from the basis
    let sk = SecretKey::from_short_lattice_basis(basis);

    // Verify the public key matches the KAT verification key
    let pk = sk.public_key();
    let pk_bytes = (&pk).to_bytes();
    assert_eq!(
        pk_bytes.as_slice(),
        &FN_DSA_KAT_512_VK[..],
        "Derived public key does not match KAT verification key"
    );

    // Extract nonce and seed from KAT data
    let nonce: [u8; 40] = FN_DSA_KAT_512_RND[0..40].try_into().unwrap();
    let seed: [u8; 56] = FN_DSA_KAT_512_RND[40..96].try_into().unwrap();

    // Sign using the test method with fixed nonce and seed
    // Use ChaCha20PRNG to match the C reference implementation
    let message = b"data1";
    let s2 = sk.sign_shake256_inner::<ChaCha20PRNG>(message, &nonce, &seed);

    // Verify the signature matches the expected KAT value
    for i in 0..N {
        assert_eq!(
            s2[i], FN_DSA_KAT_512_SIG_RAW[i],
            "Signature mismatch at coefficient {}: got {}, expected {}",
            i, s2[i], FN_DSA_KAT_512_SIG_RAW[i]
        );
    }
}

/// Tests sign_poly against the fn-dsa C reference implementation KAT vectors.
///
/// This test verifies that our sign_poly implementation produces the correct signature
/// when given the same inputs (basis, hash-to-point result, PRNG seed) as the C reference
/// implementation. This ensures compatibility with the upstream fn-dsa library.
#[test]
fn test_sign_poly_against_c_reference_kat() {
    use data::{
        FN_DSA_KAT_512_BIG_F, FN_DSA_KAT_512_BIG_G, FN_DSA_KAT_512_F, FN_DSA_KAT_512_G,
        FN_DSA_KAT_512_RND, FN_DSA_KAT_512_SIG_RAW, FN_DSA_KAT_512_VK,
    };
    use fn_dsa_sign::{
        flr::FLR,
        poly::{self, FFT},
        sign_core::sign_poly,
        tests::ChaCha20PRNG,
        DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON,
    };

    const LOGN: u32 = 9;
    const N: usize = 512;

    // Build the FFT basis from f, g, F, G
    // The basis is B = [[g, -f], [G, -F]] stored as [b00, b01, b10, b11]
    // where b00 = FFT(g), b01 = FFT(-f), b10 = FFT(G), b11 = FFT(-F)
    let mut basis = [FLR::ZERO; 4 * N];
    let (b00, rest) = basis.split_at_mut(N);
    let (b01, rest) = rest.split_at_mut(N);
    let (b10, b11) = rest.split_at_mut(N);

    // Set small polynomials and convert to FFT domain
    poly::poly_set_small(LOGN, b01, &FN_DSA_KAT_512_F);
    poly::poly_set_small(LOGN, b00, &FN_DSA_KAT_512_G);
    poly::poly_set_small(LOGN, b11, &FN_DSA_KAT_512_BIG_F);
    poly::poly_set_small(LOGN, b10, &FN_DSA_KAT_512_BIG_G);
    FFT(LOGN, b01);
    FFT(LOGN, b00);
    FFT(LOGN, b11);
    FFT(LOGN, b10);
    poly::poly_neg(LOGN, b01);
    poly::poly_neg(LOGN, b11);

    // Compute hash-to-point using the original Falcon rules
    // For original Falcon: hash = SHAKE256(nonce || message)
    let nonce = &FN_DSA_KAT_512_RND[0..40];
    let message = b"data1";

    // Hash the verification key for the hash-to-point input
    let mut hvk = [0u8; 64];
    {
        use fn_dsa_comm::shake::SHAKE256;
        let mut sh = SHAKE256::new();
        sh.inject(&FN_DSA_KAT_512_VK);
        sh.flip();
        sh.extract(&mut hvk);
    }

    // Compute hash-to-point
    let mut hm = [0u16; N];
    fn_dsa_comm::hash_to_point(nonce, &hvk, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, message, &mut hm);

    // Extract the PRNG seed (bytes 40-95 of KAT_512_RND)
    let seed: [u8; 56] = FN_DSA_KAT_512_RND[40..96].try_into().unwrap();

    // Allocate temporary buffer
    let mut tmp = [FLR::ZERO; 9 * N];

    // Sign using sign_poly with ChaCha20PRNG
    let s2 = sign_poly::<ChaCha20PRNG>(LOGN, &hm, &seed, &basis, &mut tmp);

    // Verify the signature matches the expected KAT value
    assert_eq!(s2.len(), N);
    for i in 0..N {
        assert_eq!(
            s2[i], FN_DSA_KAT_512_SIG_RAW[i],
            "Mismatch at coefficient {}: got {}, expected {}",
            i, s2[i], FN_DSA_KAT_512_SIG_RAW[i]
        );
    }
}
