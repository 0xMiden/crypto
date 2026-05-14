//! Eidos — VM-layer hash function built on BlakeG.
//!
//! This module owns padding, domain separation, mode bits, and the public API.
//! It calls into `BlakeG::compress` for the underlying compression work.
//!
//! See `SPEC.md` (§4) for the full specification and design rationale.

use super::primitive::BlakeG;
#[cfg(test)]
use super::primitive::IV;
use crate::{Felt, Word, field::BasedVectorSpace};

// CONSTANTS
// ================================================================================================

/// Number of felts per block in felt mode.
pub const RATE: usize = 8;

/// Number of felts in a digest (Word width).
pub const DIGEST_WIDTH: usize = 4;

/// Mode bit distinguishing felt-mode (0) from byte-mode (`MODE_BIT`) in the init.
const MODE_BIT: u32 = 1 << 31;

/// Felt-mode tag value injected into the domain slot at init.
const FELT_MODE: u32 = 0;

/// Byte-mode tag value injected into the domain slot at init.
const BYTE_MODE: u32 = MODE_BIT;

/// Maximum user-specified domain (31 bits; the top bit is reserved for `MODE_BIT`).
const MAX_DOMAIN: u32 = (1 << 31) - 1;

// PACKED-FELT INIT BASE CONSTANTS
// ================================================================================================
//
// These are the four `Felt`s of the initial chaining value before `domain` and `n`
// are added. They were independently verified by hand (SPEC §4.4).

/// `pack(IV[0], IV[1])`: low 32 bits = `IV[0]`, high 32 bits = `IV[1] & 0x7fff_ffff`.
const BASE0: u64 = 0x3b67_ae85_6a09_e667;

/// `pack(IV[2], IV[3])`: low 32 bits = `IV[2]`, high 32 bits = `IV[3] & 0x7fff_ffff`.
const BASE1: u64 = 0x254f_f53a_3c6e_f372;

/// `pack(0, IV[5])`: low 32 bits reserved for `domain + MODE_BIT`, high 32 bits = `IV[5] &
/// 0x7fff_ffff`.
const BASE2: u64 = 0x1b05_688c_0000_0000;

/// `pack(0, IV[7])`: low 32 bits reserved for `n`, high 32 bits = `IV[7] & 0x7fff_ffff`.
const BASE3: u64 = 0x5be0_cd19_0000_0000;

// PACKING HELPERS
// ================================================================================================

/// Pack two `u32` lanes into a single `Felt` using the Goldilocks-safe convention.
///
/// The top bit of `hi` is forced to zero so the resulting 64-bit value fits in
/// `[0, 2^63)`, which is unambiguously canonical in Goldilocks. This is the source of
/// the one-bit-per-felt entropy loss documented in SPEC §5.5.
#[inline]
fn pack(lo: u32, hi: u32) -> Felt {
    Felt::new_unchecked((((hi & 0x7fff_ffff) as u64) << 32) | lo as u64)
}

/// Unpack a `Felt` into its two `u32` lanes via canonical-form decomposition.
#[inline]
fn unpack(f: Felt) -> (u32, u32) {
    let v = f.as_canonical_u64();
    (v as u32, (v >> 32) as u32)
}

/// Convert a 4-felt `Word` to its 8-`u32` chaining-value representation.
#[inline]
fn unpack_to_cv(w: Word) -> [u32; 8] {
    let (a, b) = unpack(w[0]);
    let (c, d) = unpack(w[1]);
    let (e, f) = unpack(w[2]);
    let (g, h) = unpack(w[3]);
    [a, b, c, d, e, f, g, h]
}

/// Convert an 8-`u32` chaining value to a 4-felt `Word`, applying BlakeG's
/// output mask to the high lane of each Felt.
///
/// This is an output-finalization rule; input Felts are decoded canonically by
/// [`unpack`].
#[inline]
fn pack_to_word(cv: [u32; 8]) -> Word {
    Word::new([pack(cv[0], cv[1]), pack(cv[2], cv[3]), pack(cv[4], cv[5]), pack(cv[6], cv[7])])
}

// INITIAL CHAINING VALUE
// ================================================================================================

/// Construct the initial chaining value for a hash of length `n` under `domain` in `mode`.
///
/// See SPEC §4.4 for the formula:
/// ```text
/// cv_0 = pack(BASE0, BASE1, BASE2 + (domain + mode), BASE3 + n)
/// ```
fn init_cv(domain: u32, mode: u32, n: u32) -> [u32; 8] {
    debug_assert!(domain <= MAX_DOMAIN, "domain must fit in 31 bits");
    debug_assert!(mode == FELT_MODE || mode == BYTE_MODE, "mode must be FELT_MODE or BYTE_MODE");

    let init_word = Word::new([
        Felt::new_unchecked(BASE0),
        Felt::new_unchecked(BASE1),
        Felt::new_unchecked(BASE2 + (domain as u64) + (mode as u64)),
        Felt::new_unchecked(BASE3 + n as u64),
    ]);
    unpack_to_cv(init_word)
}

// BLOCK ENCODERS
// ================================================================================================

/// Encode 64 bytes into a 16-`u32` block, little-endian.
///
/// Unused trailing positions are zero-padded (caller guarantees `chunk.len() <= 64`).
#[inline]
fn encode_byte_block(chunk: &[u8]) -> [u32; 16] {
    debug_assert!(chunk.len() <= 64);
    let mut block = [0u32; 16];
    for (i, four) in chunk.chunks(4).enumerate() {
        let mut buf = [0u8; 4];
        buf[..four.len()].copy_from_slice(four);
        block[i] = u32::from_le_bytes(buf);
    }
    block
}

// EIDOS PUBLIC API
// ================================================================================================

/// Eidos: VM-layer hash function over BlakeG.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Eidos;

impl Eidos {
    /// Hash a sequence of bytes.
    ///
    /// Operates in byte mode: 64-byte blocks, length `n` = number of input bytes.
    /// Distinct from [`Eidos::hash_elements`] via the mode bit in init.
    pub fn hash(bytes: &[u8]) -> Word {
        let n = u32::try_from(bytes.len()).expect("input too long: byte count must fit in u32");

        let mut cv = init_cv(0, BYTE_MODE, n);

        // Empty input still hashes one zero block (SPEC §4.7).
        if bytes.is_empty() {
            let block = [0u32; 16];
            cv = BlakeG::compress(cv, block);
            return pack_to_word(cv);
        }

        for chunk in bytes.chunks(64) {
            let block = encode_byte_block(chunk);
            cv = BlakeG::compress(cv, block);
        }

        pack_to_word(cv)
    }

    /// Hash a sequence of elements (anything decomposable into felts) under domain 0.
    #[inline]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        Self::hash_elements_in_domain(elements, Felt::ZERO)
    }

    /// Hash a sequence of elements under a user-specified domain.
    ///
    /// Operates in felt mode: 8-felt blocks, length `n` = number of input felts.
    /// Distinct from [`Eidos::hash`] via the mode bit in init.
    ///
    /// **Zero-allocation**: streams felts directly into a stack-allocated 16-`u32` block
    /// buffer. Two passes over `elements` — one to compute the total felt count for `n`
    /// in init, one to absorb. No intermediate `Vec` is constructed.
    ///
    /// # Panics
    ///
    /// Panics if `domain.as_canonical_u64() > 2^31 - 1` (top bit reserved for mode).
    pub fn hash_elements_in_domain<E: BasedVectorSpace<Felt>>(
        elements: &[E],
        domain: Felt,
    ) -> Word {
        let domain_u32 = {
            let d = domain.as_canonical_u64();
            assert!(d <= MAX_DOMAIN as u64, "domain must fit in 31 bits");
            d as u32
        };

        // Pass 1: total felt count.
        let n_total: usize = elements.iter().map(|e| E::as_basis_coefficients_slice(e).len()).sum();
        let n = u32::try_from(n_total).expect("input too long: felt count must fit in u32");

        let mut cv = init_cv(domain_u32, FELT_MODE, n);

        // Empty input still hashes one zero block (SPEC §4.7).
        if n == 0 {
            cv = BlakeG::compress(cv, [0u32; 16]);
            return pack_to_word(cv);
        }

        // Pass 2: stream felts into a stack-allocated block buffer; compress when full.
        // Final partial block is naturally zero-padded since `block` is reset to all-zeros
        // after each compression.
        let mut block = [0u32; 16];
        let mut pos = 0usize; // felt position within current block, in [0, RATE)

        for elem in elements {
            for &f in E::as_basis_coefficients_slice(elem) {
                let (lo, hi) = unpack(f);
                block[2 * pos] = lo;
                block[2 * pos + 1] = hi;
                pos += 1;
                if pos == RATE {
                    cv = BlakeG::compress(cv, block);
                    block = [0u32; 16];
                    pos = 0;
                }
            }
        }

        if pos != 0 {
            cv = BlakeG::compress(cv, block);
        }

        pack_to_word(cv)
    }

    /// Hash two `Word` values into one. Equivalent to hashing the 8-felt concatenation
    /// under domain 0.
    #[inline]
    pub fn merge(values: &[Word; 2]) -> Word {
        Self::merge_in_domain(values, Felt::ZERO)
    }

    /// Hash two `Word` values into one under a user-specified domain.
    #[inline]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        // Stack-allocated [Felt; 8]; hash_elements_in_domain is zero-alloc.
        let elements: [Felt; 8] = [
            values[0][0],
            values[0][1],
            values[0][2],
            values[0][3],
            values[1][0],
            values[1][1],
            values[1][2],
            values[1][3],
        ];
        Self::hash_elements_in_domain(&elements, domain)
    }

    /// Hash a sequence of `Word`s into one. Equivalent to hashing the concatenation
    /// of all the felts via the felt-mode hash.
    #[inline]
    pub fn merge_many(values: &[Word]) -> Word {
        // Zero-copy view of [Word] as [Felt].
        Self::hash_elements(Word::words_as_elements(values))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn base_constants_match_iv() {
        // Verify that BASE0..BASE3 are exactly what SPEC §4.4 says they are:
        //   BASE0 = pack(IV[0], IV[1])
        //   BASE1 = pack(IV[2], IV[3])
        //   BASE2 = pack(0, IV[5])
        //   BASE3 = pack(0, IV[7])
        assert_eq!(BASE0, pack(IV[0], IV[1]).as_canonical_u64());
        assert_eq!(BASE1, pack(IV[2], IV[3]).as_canonical_u64());
        assert_eq!(BASE2, pack(0, IV[5]).as_canonical_u64());
        assert_eq!(BASE3, pack(0, IV[7]).as_canonical_u64());
    }

    #[test]
    fn pack_unpack_roundtrip_in_subspace() {
        // Values within the 252-bit subspace must round-trip losslessly.
        let lo = 0x1234_5678u32;
        let hi = 0x4abc_def0u32; // top bit clear
        let f = pack(lo, hi);
        let (lo_out, hi_out) = unpack(f);
        assert_eq!(lo_out, lo);
        assert_eq!(hi_out, hi);
    }

    #[test]
    fn pack_masks_top_bit_of_high_lane() {
        // Top bit of `hi` must be masked away.
        let lo = 0u32;
        let hi = 0xffff_ffffu32;
        let f = pack(lo, hi);
        let (_, hi_out) = unpack(f);
        assert_eq!(hi_out, 0x7fff_ffff);
    }

    #[test]
    fn init_cv_layout_for_felt_mode() {
        let cv = init_cv(7, FELT_MODE, 42);
        // Reconstruct what we expect given BASE0..BASE3 + domain + n.
        let expected_word = Word::new([
            Felt::new_unchecked(BASE0),
            Felt::new_unchecked(BASE1),
            Felt::new_unchecked(BASE2 + 7), // domain=7, mode=0
            Felt::new_unchecked(BASE3 + 42),
        ]);
        let expected_cv = unpack_to_cv(expected_word);
        assert_eq!(cv, expected_cv);
    }

    #[test]
    fn init_cv_layout_for_byte_mode() {
        let cv = init_cv(7, BYTE_MODE, 42);
        let expected_word = Word::new([
            Felt::new_unchecked(BASE0),
            Felt::new_unchecked(BASE1),
            Felt::new_unchecked(BASE2 + 7 + (MODE_BIT as u64)),
            Felt::new_unchecked(BASE3 + 42),
        ]);
        let expected_cv = unpack_to_cv(expected_word);
        assert_eq!(cv, expected_cv);
    }

    #[test]
    fn init_cv_lives_in_252_bit_subspace() {
        let cv = init_cv(0, FELT_MODE, 0);
        assert_eq!(cv[1] & !0x7fff_ffff, 0);
        assert_eq!(cv[3] & !0x7fff_ffff, 0);
        assert_eq!(cv[5] & !0x7fff_ffff, 0);
        assert_eq!(cv[7] & !0x7fff_ffff, 0);
    }

    #[test]
    fn empty_inputs_use_one_zero_block() {
        // Both modes hash an empty input via one zero-block compression.
        // The two outputs must differ (mode separation).
        let bytes_digest = Eidos::hash(&[]);
        let felts_digest = Eidos::hash_elements::<Felt>(&[]);
        assert_ne!(bytes_digest, felts_digest);
    }

    #[test]
    fn hash_elements_is_deterministic() {
        let xs = vec![Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];
        let a = Eidos::hash_elements(&xs);
        let b = Eidos::hash_elements(&xs);
        assert_eq!(a, b);
    }
}
