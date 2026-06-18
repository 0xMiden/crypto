//! Reference model for the Eidos u32-XOR AEAD stream.
//!
//! This module is for tests and VM-vector generation. It does not manage
//! nonces. Production callers must never reuse `(key, nonce)` and must not
//! repeat counter blocks under a fixed CTR key.

use alloc::vec::Vec;

use super::{
    Eidos,
    framing::{compress_felt_block, encode_felt_block, unpack_to_cv, unpack_u32_pair},
    primitive::BlakeG,
};
use crate::{
    Felt, Word,
    field::{BasedVectorSpace, BinomialExtensionField},
};

/// Domain for deriving the AEAD CTR chaining value.
pub const AEAD_CTR_DOMAIN: u32 = 0x000a_ead0;
/// Domain for deriving the AEAD MAC key.
pub const AEAD_MAC_DOMAIN: u32 = 0x000a_ead1;

const FELTS_PER_CTR_BLOCK: usize = 4;
const LIMBS_PER_CTR_BLOCK: usize = 2 * FELTS_PER_CTR_BLOCK;
const MAC_BATCH_FELTS: usize = 8;

type QuadFelt = BinomialExtensionField<Felt, 2>;

/// Domain-separates `(key, nonce)` and compresses to a CTR chaining value via
/// Eidos.
///
/// The returned word is a masked Eidos digest with 252 bits of entropy, usable
/// as an input CV to [`BlakeG::compress_raw`] for keystream generation.
pub fn derive_ctr_key(key: Word, nonce: Word) -> Word {
    // Fixed-arity derivations use the domain tag for separation; variable-length
    // Eidos hashes bind length in the initial chaining value.
    let init = Eidos::init_chaining_word(AEAD_CTR_DOMAIN, 0);
    compress_felt_block(
        init,
        [key[0], key[1], key[2], key[3], nonce[0], nonce[1], nonce[2], nonce[3]],
    )
}

/// Domain-separates `(key, nonce)` and compresses to a MAC key via Eidos.
///
/// The returned word is `[r0, r1, s0, s1]`, where `r = (r0, r1)` is the
/// quadratic-extension evaluation point and `s = (s0, s1)` is the final mask.
pub fn derive_mac_key(key: Word, nonce: Word) -> Word {
    // Fixed-arity derivations use the domain tag for separation; variable-length
    // Eidos hashes bind length in the initial chaining value.
    let init = Eidos::init_chaining_word(AEAD_MAC_DOMAIN, 0);
    compress_felt_block(
        init,
        [key[0], key[1], key[2], key[3], nonce[0], nonce[1], nonce[2], nonce[3]],
    )
}

/// Returns eight raw u32 keystream limbs for one counter block.
pub fn keystream_block(ctr_key: Word, counter: u32) -> [u32; 8] {
    let cv = unpack_to_cv(ctr_key);
    let mut counter_block = [Felt::ZERO; 8];
    counter_block[0] = Felt::from_u32(counter);

    BlakeG::compress_raw(cv, encode_felt_block(&counter_block))
}

/// Encrypts canonical field elements as expanded u32 limbs.
///
/// Each plaintext Felt becomes two ciphertext Felts, each holding one u32 limb.
/// Security requires a unique `(key, nonce)` per message.
pub fn encrypt_felts_expanded(key: Word, nonce: Word, plaintext: &[Felt]) -> Vec<Felt> {
    assert!(counter_fits_len(plaintext.len()), "AEAD supports at most 2^32 CTR blocks",);

    let ctr_key = derive_ctr_key(key, nonce);
    let mut ciphertext = Vec::with_capacity(plaintext.len() * 2);

    for (counter, chunk) in plaintext.chunks(FELTS_PER_CTR_BLOCK).enumerate() {
        let counter = u32::try_from(counter).expect("counter bound checked above");
        let keystream = keystream_block(ctr_key, counter);
        for (i, &felt) in chunk.iter().enumerate() {
            let (lo, hi) = unpack_u32_pair(felt);
            ciphertext.push(Felt::from_u32(lo ^ keystream[2 * i]));
            ciphertext.push(Felt::from_u32(hi ^ keystream[2 * i + 1]));
        }
    }

    ciphertext
}

/// Decrypts expanded u32-limb ciphertext produced by [`encrypt_felts_expanded`].
///
/// Returns `None` if the ciphertext is too long for the u32 counter, the length
/// is odd, a ciphertext limb is not a canonical u32 value, or the decrypted limb
/// pair is not a canonical Felt.
pub fn decrypt_felts_expanded(key: Word, nonce: Word, ciphertext: &[Felt]) -> Option<Vec<Felt>> {
    if ciphertext.len() % 2 != 0 {
        return None;
    }

    if !counter_fits_len(ciphertext.len() / 2) {
        return None;
    }

    let ctr_key = derive_ctr_key(key, nonce);
    let mut plaintext = Vec::with_capacity(ciphertext.len() / 2);

    for (counter, chunk) in ciphertext.chunks(LIMBS_PER_CTR_BLOCK).enumerate() {
        let counter = u32::try_from(counter).ok()?;
        let keystream = keystream_block(ctr_key, counter);
        for (felt_in_block, pair) in chunk.chunks(2).enumerate() {
            let c_lo = u32_limb(pair[0])?;
            let c_hi = u32_limb(pair[1])?;
            let lo = c_lo ^ keystream[2 * felt_in_block];
            let hi = c_hi ^ keystream[2 * felt_in_block + 1];
            plaintext.push(pack_canonical(lo, hi)?);
        }
    }

    Some(plaintext)
}

/// Authenticates expanded u32-limb ciphertext.
///
/// This is the production AEAD tag direction. Associated data is included before
/// the ciphertext. Lengths are measured in Felts and appended as
/// `[ad_len, ct_len]`; the coefficient stream is padded to an 8-Felt boundary.
/// The MAC polynomial is evaluated over the quadratic extension by pairing
/// adjacent Felts into one extension coefficient.
pub fn auth_tag_expanded(
    key: Word,
    nonce: Word,
    associated_data: &[Felt],
    ciphertext: &[Felt],
) -> [Felt; 2] {
    assert!(
        associated_data.len() <= u32::MAX as usize,
        "AEAD supports at most 2^32 AD Felts",
    );
    assert!(
        ciphertext.len() <= u32::MAX as usize,
        "AEAD supports at most 2^32 ciphertext Felts",
    );
    assert!(
        ciphertext.iter().all(|&limb| u32_limb(limb).is_some()),
        "expanded ciphertext limbs must be canonical u32 Felts",
    );

    let mut coefficients = Vec::with_capacity(
        Word::NUM_ELEMENTS + associated_data.len() + ciphertext.len() + 2 + MAC_BATCH_FELTS,
    );

    coefficients.extend(nonce.into_elements());
    coefficients.extend_from_slice(associated_data);
    coefficients.extend_from_slice(ciphertext);
    coefficients.push(Felt::from_u32(associated_data.len() as u32));
    coefficients.push(Felt::from_u32(ciphertext.len() as u32));
    while coefficients.len() % MAC_BATCH_FELTS != 0 {
        coefficients.push(Felt::ZERO);
    }

    let mac_key = derive_mac_key(key, nonce);
    let evaluation_point = quad_from_pair(mac_key[0], mac_key[1]);
    let mask = quad_from_pair(mac_key[2], mac_key[3]);
    let tag = evaluate_mac_polynomial(&coefficients, evaluation_point) + mask;
    let tag_coefficients = tag.as_basis_coefficients_slice();
    [tag_coefficients[0], tag_coefficients[1]]
}

/// Encrypts and authenticates field elements using expanded u32-limb ciphertext.
pub fn encrypt_felts_expanded_authenticated(
    key: Word,
    nonce: Word,
    associated_data: &[Felt],
    plaintext: &[Felt],
) -> (Vec<Felt>, [Felt; 2]) {
    let ciphertext = encrypt_felts_expanded(key, nonce, plaintext);
    let tag = auth_tag_expanded(key, nonce, associated_data, &ciphertext);
    (ciphertext, tag)
}

fn u32_limb(value: Felt) -> Option<u32> {
    u32::try_from(value.as_canonical_u64()).ok()
}

fn pack_canonical(lo: u32, hi: u32) -> Option<Felt> {
    Felt::new(((hi as u64) << 32) | lo as u64).ok()
}

fn counter_fits_len(num_felts: usize) -> bool {
    // ceil(num_felts / FELTS_PER_CTR_BLOCK) <= 2^32.
    let num_felts = num_felts as u64;
    let block_size = FELTS_PER_CTR_BLOCK as u64;
    let full_blocks = num_felts / block_size;
    let has_partial_block = u64::from(num_felts % block_size != 0);

    full_blocks + has_partial_block <= u64::from(u32::MAX) + 1
}

fn evaluate_mac_polynomial(coefficients: &[Felt], alpha: QuadFelt) -> QuadFelt {
    debug_assert_eq!(coefficients.len() % 2, 0);

    coefficients
        .chunks_exact(2)
        .fold(quad_from_pair(Felt::ZERO, Felt::ZERO), |acc, coefficient| {
            acc * alpha + quad_from_pair(coefficient[0], coefficient[1])
        })
}

fn quad_from_pair(c0: Felt, c1: Felt) -> QuadFelt {
    QuadFelt::new([c0, c1])
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(Felt::new_unchecked))
    }

    fn key() -> Word {
        word([1, 2, 3, 4])
    }

    fn nonce() -> Word {
        word([0x10, 0x20, 0x30, 0x40])
    }

    #[test]
    fn expanded_limb_encryption_roundtrips_edge_felts() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];

        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let decrypted = decrypt_felts_expanded(key(), nonce(), &ciphertext).unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() * 2);
        assert!(ciphertext.iter().all(|&limb| u32_limb(limb).is_some()));
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn expanded_limb_decryption_rejects_malformed_ciphertext() {
        let odd_len = vec![Felt::from_u32(1)];
        assert!(decrypt_felts_expanded(key(), nonce(), &odd_len).is_none());

        let non_u32_limb = vec![Felt::new_unchecked(1u64 << 40), Felt::ZERO];
        assert!(decrypt_felts_expanded(key(), nonce(), &non_u32_limb).is_none());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn counter_limit_is_explicit() {
        let max_felts = (u64::from(u32::MAX) + 1) * FELTS_PER_CTR_BLOCK as u64;

        assert!(counter_fits_len(max_felts as usize));
        assert!(!counter_fits_len((max_felts + 1) as usize));
    }

    #[test]
    fn reference_vector_for_expanded_limb_encryption() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];

        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let expected = vec![
            Felt::from_u32(0xf1b1_faf2),
            Felt::from_u32(0xb516_6354),
            Felt::from_u32(0xf063_24fe),
            Felt::from_u32(0x72f2_0f8d),
            Felt::from_u32(0x7945_2ccf),
            Felt::from_u32(0x28e5_c557),
            Felt::from_u32(0x59fc_5080),
            Felt::from_u32(0x7896_8ab9),
            Felt::from_u32(0x8616_0fdd),
            Felt::from_u32(0x6cf8_c822),
        ];

        assert_eq!(ciphertext, expected);
        assert_eq!(decrypt_felts_expanded(key(), nonce(), &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn reference_vector_for_expanded_authentication() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];
        let associated_data = [Felt::new_unchecked(5), Felt::new_unchecked(6)];
        let ciphertext = encrypt_felts_expanded(key(), nonce(), &plaintext);
        let tag = auth_tag_expanded(key(), nonce(), &associated_data, &ciphertext);
        let expected = [
            Felt::new_unchecked(6127600617032766561),
            Felt::new_unchecked(13291603915237176549),
        ];

        assert_eq!(tag, expected);
    }

    #[test]
    fn auth_tag_changes_with_ciphertext_and_lengths() {
        let plaintext = vec![
            Felt::ZERO,
            Felt::new_unchecked(1 << 63),
            Felt::new(Felt::ORDER - 1).unwrap(),
            Felt::new_unchecked(0x0123_4567_89ab_cdef),
            Felt::new_unchecked(42),
        ];
        let (ciphertext, tag) =
            encrypt_felts_expanded_authenticated(key(), nonce(), &[], &plaintext);

        let mut forged = ciphertext.clone();
        forged[0] += Felt::ONE;
        assert_ne!(auth_tag_expanded(key(), nonce(), &[], &forged), tag);

        let truncated = ciphertext[..ciphertext.len() - 2].to_vec();
        assert_ne!(auth_tag_expanded(key(), nonce(), &[], &truncated), tag);
    }
}
