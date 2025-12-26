use alloc::vec::Vec;

use data::{
    EXPECTED_SIG, EXPECTED_SIG_POLYS, NUM_TEST_VECTORS, SK_POLYS, SYNC_DATA_FOR_TEST_VECTOR,
};
use prng::Shake256Testing;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{Serializable, math::Polynomial};
use crate::dsa::falcon512_rpo::{
    PREVERSIONED_NONCE, PREVERSIONED_NONCE_LEN, SIG_NONCE_LEN, SIG_POLY_BYTE_LEN, SecretKey,
    tests::data::DETERMINISTIC_SIGNATURE,
};

mod data;
mod prng;
pub(crate) use prng::ChaCha;

/// Tests the Falcon512 implementation using the test vectors in
/// https://github.com/tprest/falcon.py/blob/88d01ede1d7fa74a8392116bc5149dee57af93f2/scripts/sign_KAT.py#L1131
#[test]
fn test_signature_gen_reference_impl() {
    // message and initial seed used for generating the test vectors in the reference implementation
    let message = b"data1";
    let seed = b"external";

    // the reference implementation uses SHAKE256 for generating:
    // 1. The nonce for the hash-to-point algorithm.
    // 2. The seed used for initializing the ChaCha20 PRNG which is used in signature generation.
    let mut rng_shake = Shake256Testing::new(seed.to_vec());

    // the test vectors in the reference implementation include test vectors for signatures with
    // parameter N = 2^i for i = 1..10, where N is the exponent of the monic irreducible polynomial
    // phi. We are only interested in the test vectors for N = 2^9 = 512 and thus need to "sync"
    // the SHAKE256 PRNG before we can use it in testing the test vectors that are relevant for
    // N = 512.
    // The following makes the necessary calls to the PRNG in order to prepare it for use with
    // the test vectors for N = 512.
    rng_shake.sync_rng();

    for i in 0..NUM_TEST_VECTORS {
        // construct the four polynomials defining the secret key for this test vector
        let [f, g, big_f, big_g] = SK_POLYS[i];
        let f = Polynomial::new(f.to_vec());
        let g = Polynomial::new(g.to_vec());
        let big_f = Polynomial::new(big_f.to_vec());
        let big_g = Polynomial::new(big_g.to_vec());

        // we generate the secret key using the above four polynomials
        let sk = SecretKey::from_short_lattice_basis([g, f, big_g, big_f]);

        // we compare the signature as a polynomial

        // 1. first we synchronize the `SHAKE256` context with the one in the reference C
        // implementation as done in https://github.com/tprest/falcon.py/blob/88d01ede1d7fa74a8392116bc5149dee57af93f2/test.py#L256
        let skip_bytes = SYNC_DATA_FOR_TEST_VECTOR[i].0 * 8;
        let mut dummy = vec![0_u8; skip_bytes];
        rng_shake.fill_bytes(&mut dummy);

        // 2. generate the signature
        let signature = sk.sign_with_rng_testing(message, &mut rng_shake);

        // 3. compare against the expected signature
        let sig_coef: Vec<i16> =
            signature.sig_poly().coefficients.iter().map(|c| c.balanced_value()).collect();
        assert_eq!(sig_coef, EXPECTED_SIG_POLYS[i]);

        // 4. compare the encoded signatures including the nonce
        let sig_bytes = &signature.to_bytes();
        let expected_sig_bytes = EXPECTED_SIG[i];
        let hex_expected_sig_bytes = hex::decode(expected_sig_bytes).unwrap();
        // to compare against the test vectors we:
        // 1. remove the headers when comparing as RPO_FALCON512 uses a different header format,
        // 2. compare the nonce part separately as the deterministic version we use omits the
        //    inclusion of the preversioned portion of the nonce by in its serialized format,
        // 3. we remove the public key from the RPO_FALCON512 signature as this is not part of the
        //    signature in the reference implementation,
        // 4. remove the nonce version byte, in addition to the header, from `sig_bytes`.
        let nonce = signature.nonce();
        assert_eq!(hex_expected_sig_bytes[1..1 + SIG_NONCE_LEN], nonce.as_bytes());
        assert_eq!(
            &hex_expected_sig_bytes[1 + SIG_NONCE_LEN..],
            &sig_bytes[2..2 + SIG_POLY_BYTE_LEN]
        );
    }
}

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
fn test_flr_and_legacy_signing_match() {
    use crate::Word;
    use crate::dsa::falcon512_rpo::{Nonce, hash_to_point::hash_to_point_rpo256};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let message = Word::new([crate::ONE; 4]);
    let iterations = 10;

    for i in 0..iterations {
        // Generate a fresh key with unique seed
        let mut keygen_seed = [0u8; 32];
        keygen_seed[0] = i;
        let mut rng = ChaCha20Rng::from_seed(keygen_seed);
        let sk = SecretKey::with_rng(&mut rng);

        // Hash message to polynomial
        let nonce = Nonce::deterministic();
        let c = hash_to_point_rpo256(message, &nonce);

        // Create two RNGs with the same seed for signing
        let mut signing_seed = [0u8; 32];
        signing_seed[0] = i;
        signing_seed[1] = 0xff;
        let mut rng_flr = ChaCha20Rng::from_seed(signing_seed);
        let mut rng_legacy = ChaCha20Rng::from_seed(signing_seed);

        // Sign with both methods
        let sig_flr = sk.sign_helper(c.clone(), &mut rng_flr);
        let sig_legacy = sk.sign_helper_legacy(c, &mut rng_legacy);

        // Compare signatures
        let sig_flr_coef: Vec<i16> =
            sig_flr.coefficients.iter().map(|c| c.balanced_value()).collect();
        let sig_legacy_coef: Vec<i16> =
            sig_legacy.coefficients.iter().map(|c| c.balanced_value()).collect();

        assert_eq!(
            sig_flr_coef, sig_legacy_coef,
            "Iteration {}: FLR and legacy signatures should match",
            i
        );
    }
}

#[test]
fn test_ntru_gen_opt_kat() {
    
    use sha2::{Sha256, Digest};
    use std::println;

    // KAT from fn-dsa-kgen for Falcon512 (logn=9)
    const KAT_KG512: [&str; 5] = [
        "e5b8d48e5ce74c62e3e0ccd40f7ce5762d3a329d5b85bfbb3af88d31bdceb3e6",
        "2771383de7a38daef285c71494fb0ab438be6a03843b7936901b831d0e846f3a",
        "4850f28b3cc310a01abdd6091ffcb1012102da51146bf47fb4045c9527daf22f",
        "7e2db5bed6b3d656b12bb33b7432fc4929bf56c69cf73db9b5ed56c29472d775",
        "8e4dd3c29b862bf392dfe1a97ef89991faef86987b6d8dca2140af316b47b260",
    ];

    let n = 512;
    println!("\n=== Testing ntru_gen_opt against fn-dsa KAT ===\n");

    for i in 0..KAT_KG512.len() {
        let seed = if i < 10 {
            format!("test{}", i)
        } else {
            format!("test{}{}", i / 10, i % 10)
        };

        println!("Test {}: seed = '{}'", i, seed);

        // Use fn-dsa-comm's SHAKE256_PRNG exactly as fn-dsa-kgen does
        use crate::dsa::falcon512_rpo::math::ntru_gen_fndsa;
        use fn_dsa_comm::{PRNG, shake::SHAKE256_PRNG};

        let mut rng = <SHAKE256_PRNG as PRNG>::new(seed.as_bytes());
        let [g, f, big_g, big_f] = ntru_gen_fndsa(n, &mut rng);

        // Hash in fn-dsa order: [f, g, F, G]
        let mut hasher = Sha256::new();
        for &coef in &f.coefficients {
            Digest::update(&mut hasher, &[coef as u8]);
        }
        for &coef in &g.coefficients {
            Digest::update(&mut hasher, &[coef as u8]);
        }
        for &coef in &big_f.coefficients {
            Digest::update(&mut hasher, &[coef as u8]);
        }
        for &coef in &big_g.coefficients {
            Digest::update(&mut hasher, &[coef as u8]);
        }
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        let expected = KAT_KG512[i];
        let matches = hash_hex == expected;

        println!("  Expected: {}", expected);
        println!("  Got:      {}", hash_hex);
        println!("  Match: {}\n", matches);

        assert_eq!(hash_hex, expected, "KAT {} failed", i);
    }

    println!("All {} KAT tests passed!", KAT_KG512.len());
}

#[test]
fn test_sampler_direct() {
    use crate::dsa::falcon512_rpo::math::gauss_fndsa::sample_f_fndsa;
    use crate::dsa::falcon512_rpo::math::Polynomial;
    use crate::dsa::falcon512_rpo::math::FalconFelt;
    use crate::dsa::falcon512_rpo::math::FastFft;
    use crate::dsa::falcon512_rpo::math::ntru_opt;
    use num::Zero;
    use std::println;

    println!("\n=== Testing sample_f_fndsa directly ===\n");

    use fn_dsa_comm::{PRNG, shake::SHAKE256_PRNG};

    let mut rng = <SHAKE256_PRNG as PRNG>::new(b"test0");

    let f = sample_f_fndsa(512, &mut rng);
    let g = sample_f_fndsa(512, &mut rng);

    println!("f[0..10]: {:?}", &f[0..10]);
    println!("g[0..10]: {:?}", &g[0..10]);
    println!("f parity: {}", f.iter().map(|&x| x as i32).sum::<i32>() & 1);
    println!("g parity: {}", g.iter().map(|&x| x as i32).sum::<i32>() & 1);

    // Check if this pair would pass fn-dsa's checks
    let f_poly = Polynomial::new(f.iter().map(|&x| x as i16).collect());
    let _g_poly = Polynomial::new(g.iter().map(|&x| x as i16).collect());

    // Check 1: Gamma1
    let mut sn = 0i32;
    for i in 0..512 {
        let xf = f[i] as i32;
        let xg = g[i] as i32;
        sn += xf * xf + xg * xg;
    }
    println!("Gamma1 check: sn = {} (limit: 16823) -> {}", sn, if sn < 16823 { "PASS" } else { "FAIL" });

    // Check 2: Invertibility
    let f_ntt = f_poly.map(|&i| FalconFelt::new(i)).fft();
    let invertible = !f_ntt.coefficients.iter().any(|e| e.is_zero());
    println!("Invertibility check: {}", if invertible { "PASS" } else { "FAIL" });

    // Check 3: Gamma2
    let mut tmp_fxr = vec![ntru_opt::fxp::FXR::ZERO; (5 * 512) / 2];
    let gamma2_ok = ntru_opt::check_ortho_norm(9, &f, &g, &mut tmp_fxr);
    println!("Gamma2 check: {}", if gamma2_ok { "PASS" } else { "FAIL" });
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
