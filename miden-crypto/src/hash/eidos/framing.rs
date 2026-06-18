//! Eidos hash framing.
//!
//! Defines Eidos packing, padding, domain/mode separation, length binding, and
//! the public hash API. The raw BlakeG compression core remains internal.

use alloc::vec::Vec;
use core::array;

use p3_symmetric::CryptographicHasher;

#[cfg(test)]
use super::primitive::IV;
use super::primitive::{BlakeG, PACKED_LANES};
use crate::{Felt, Word, field::BasedVectorSpace};

/// Number of felts absorbed per felt-mode block.
pub const RATE: usize = 8;

/// Number of felts in an Eidos digest.
pub const DIGEST_WIDTH: usize = 4;

/// Mode bit distinguishing byte mode from felt mode in the init CV.
const MODE_BIT: u32 = 1 << 31;

const FELT_MODE: u32 = 0;
const BYTE_MODE: u32 = MODE_BIT;

/// Maximum user domain. The top bit is reserved for [`MODE_BIT`].
const MAX_DOMAIN: u32 = (1 << 31) - 1;

// Initial CV bases. `BASE2` reserves its low lane for domain + mode; `BASE3`
// reserves its low lane for input length.
const BASE0: u64 = 0x3b67_ae85_6a09_e667;
const BASE1: u64 = 0x254f_f53a_3c6e_f372;
const BASE2: u64 = 0x1b05_688c_0000_0000;
const BASE3: u64 = 0x5be0_cd19_0000_0000;

/// Pack two `u32` lanes into one Goldilocks field element.
///
/// The high lane is masked before packing:
/// `pack(lo, hi) = ((hi & 0x7fff_ffff) << 32) | lo`.
#[inline]
pub(super) fn pack_u32_pair(lo: u32, hi: u32) -> Felt {
    Felt::new_unchecked((((hi & 0x7fff_ffff) as u64) << 32) | lo as u64)
}

/// Unpack a canonical field element into two `u32` lanes.
///
/// This does not check that `f` was produced by [`pack_u32_pair`].
#[inline]
pub(super) fn unpack_u32_pair(f: Felt) -> (u32, u32) {
    let v = f.as_canonical_u64();
    (v as u32, (v >> 32) as u32)
}

/// Convert a packed digest word to its eight-lane chaining value.
#[inline]
pub(super) fn unpack_to_cv(w: Word) -> [u32; 8] {
    let (a, b) = unpack_u32_pair(w[0]);
    let (c, d) = unpack_u32_pair(w[1]);
    let (e, f) = unpack_u32_pair(w[2]);
    let (g, h) = unpack_u32_pair(w[3]);
    [a, b, c, d, e, f, g, h]
}

/// Convert an eight-lane chaining value to a packed digest word.
#[inline]
pub(super) fn pack_to_word(cv: [u32; 8]) -> Word {
    Word::new([
        pack_u32_pair(cv[0], cv[1]),
        pack_u32_pair(cv[2], cv[3]),
        pack_u32_pair(cv[4], cv[5]),
        pack_u32_pair(cv[6], cv[7]),
    ])
}

#[inline]
fn pack_cv_to_felts<const LANES: usize>(cv: [[u32; LANES]; 8]) -> [[Felt; LANES]; DIGEST_WIDTH] {
    array::from_fn(|word| {
        array::from_fn(|lane| pack_u32_pair(cv[2 * word][lane], cv[2 * word + 1][lane]))
    })
}

#[inline]
fn pack_cv_to_u64s(cv: [u32; 8]) -> [u64; DIGEST_WIDTH] {
    array::from_fn(|word| pack_u32_pair_u64(cv[2 * word], cv[2 * word + 1]))
}

#[inline]
fn pack_cv_to_packed_u64s<const LANES: usize>(
    cv: [[u32; LANES]; 8],
) -> [[u64; LANES]; DIGEST_WIDTH] {
    array::from_fn(|word| {
        array::from_fn(|lane| pack_u32_pair_u64(cv[2 * word][lane], cv[2 * word + 1][lane]))
    })
}

#[inline]
pub(super) fn pack_u32_pair_u64(lo: u32, hi: u32) -> u64 {
    (((hi & 0x7fff_ffff) as u64) << 32) | lo as u64
}

#[inline]
fn init_packed_digest<const LANES: usize>(
    domain: u32,
    mode: u32,
    n: u32,
) -> [[Felt; LANES]; DIGEST_WIDTH] {
    let cv = init_cv(domain, mode, n);
    pack_cv_to_felts(array::from_fn(|word| [cv[word]; LANES]))
}

#[inline]
fn init_packed_u64_digest<const LANES: usize>(
    domain: u32,
    mode: u32,
    n: u32,
) -> [[u64; LANES]; DIGEST_WIDTH] {
    let cv = init_cv(domain, mode, n);
    pack_cv_to_packed_u64s(array::from_fn(|word| [cv[word]; LANES]))
}

/// Construct the initial chaining value.
///
/// `domain`, `mode`, and input length `n` are injected before the first
/// compression, so the BlakeG primitive itself does not add domain separation.
fn init_cv(domain: u32, mode: u32, n: u32) -> [u32; 8] {
    debug_assert!(domain <= MAX_DOMAIN, "domain must fit in 31 bits");
    debug_assert!(mode == FELT_MODE || mode == BYTE_MODE, "invalid Eidos mode");

    let init_word = Word::new([
        Felt::new_unchecked(BASE0),
        Felt::new_unchecked(BASE1),
        Felt::new_unchecked(BASE2 + (domain as u64) + (mode as u64)),
        Felt::new_unchecked(BASE3 + n as u64),
    ]);
    unpack_to_cv(init_word)
}

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

#[inline]
pub(super) fn encode_felt_block(chunk: &[Felt]) -> [u32; 16] {
    debug_assert!(chunk.len() <= RATE);

    let mut block = [0u32; 16];
    for (i, &f) in chunk.iter().enumerate() {
        let (lo, hi) = unpack_u32_pair(f);
        block[2 * i] = lo;
        block[2 * i + 1] = hi;
    }
    block
}

#[inline]
fn encode_u64_block(chunk: &[u64]) -> [u32; 16] {
    debug_assert!(chunk.len() <= RATE);

    let mut block = [0u32; 16];
    for (i, &value) in chunk.iter().enumerate() {
        block[2 * i] = value as u32;
        block[2 * i + 1] = (value >> 32) as u32;
    }
    block
}

#[inline]
fn unpack_packed_digest<const LANES: usize>(
    digest: [[Felt; LANES]; DIGEST_WIDTH],
) -> [[u32; LANES]; 8] {
    let pairs = digest.map(|word| word.map(unpack_u32_pair));
    array::from_fn(|word| {
        array::from_fn(|lane| {
            let (lo, hi) = pairs[word / 2][lane];
            if word % 2 == 0 { lo } else { hi }
        })
    })
}

#[inline]
fn unpack_packed_u64_digest<const LANES: usize>(
    digest: [[u64; LANES]; DIGEST_WIDTH],
) -> [[u32; LANES]; 8] {
    array::from_fn(|word| {
        array::from_fn(|lane| {
            let value = digest[word / 2][lane];
            if word % 2 == 0 {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

#[inline]
pub(super) fn encode_packed_felt_block<const LANES: usize>(
    block: [[Felt; LANES]; RATE],
) -> [[u32; LANES]; 16] {
    let pairs = block.map(|values| values.map(unpack_u32_pair));
    array::from_fn(|word| {
        array::from_fn(|lane| {
            let (lo, hi) = pairs[word / 2][lane];
            if word % 2 == 0 { lo } else { hi }
        })
    })
}

#[inline]
fn encode_packed_u64_block<const LANES: usize>(block: [[u64; LANES]; RATE]) -> [[u32; LANES]; 16] {
    array::from_fn(|word| {
        array::from_fn(|lane| {
            let value = block[word / 2][lane];
            if word % 2 == 0 {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

/// Hash one full felt-mode block of `u64`-encoded field elements under domain 0.
#[inline]
pub(super) fn compress_u64_block(block: [u64; RATE]) -> [u64; DIGEST_WIDTH] {
    let cv = init_cv(0, FELT_MODE, RATE as u32);
    pack_cv_to_u64s(BlakeG::compress(cv, encode_u64_block(&block)))
}

/// Hash one full packed felt-mode block of `u64`-encoded field elements under domain 0.
#[inline]
pub(super) fn compress_packed_u64_block(
    block: [[u64; PACKED_LANES]; RATE],
) -> [[u64; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = init_cv(0, FELT_MODE, RATE as u32);
    let cv = array::from_fn(|word| [cv[word]; PACKED_LANES]);
    let block = encode_packed_u64_block(block);
    pack_cv_to_packed_u64s(BlakeG::compress_packed_native(cv, block))
}

/// Compress one full felt-mode block under a packed Eidos chaining word.
#[inline]
pub(super) fn compress_felt_block(cv: Word, block: [Felt; RATE]) -> Word {
    let cv = unpack_to_cv(cv);
    let block = encode_felt_block(&block);
    pack_to_word(BlakeG::compress(cv, block))
}

#[cfg(test)]
#[inline]
pub(super) fn compress_felt_digest_block(
    cv: [Felt; DIGEST_WIDTH],
    block: [Felt; RATE],
) -> [Felt; DIGEST_WIDTH] {
    compress_felt_block(Word::new(cv), block).into()
}

#[inline]
pub(super) fn compress_packed_felt_digest_block(
    cv: [[Felt; PACKED_LANES]; DIGEST_WIDTH],
    block: [[Felt; PACKED_LANES]; RATE],
) -> [[Felt; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = unpack_packed_digest(cv);
    let block = encode_packed_felt_block(block);
    pack_cv_to_felts(BlakeG::compress_packed_native(cv, block))
}

#[inline]
fn exact_size_hint<I: Iterator>(iter: &I) -> Option<usize> {
    let (lower, upper) = iter.size_hint();
    upper.filter(|&upper| upper == lower)
}

#[inline]
fn assert_yielded_len(actual: usize, expected: usize) {
    assert_eq!(actual, expected, "iterator yielded a different length than its size_hint");
}

fn hash_felt_iter_with_len<I>(iter: I, len: usize) -> [Felt; DIGEST_WIDTH]
where
    I: Iterator<Item = Felt>,
{
    let n = u32::try_from(len).expect("input too long: felt count must fit in u32");
    let mut cv = init_cv(0, FELT_MODE, n);
    let mut block = [0u32; 16];
    let mut pos = 0usize;
    let mut count = 0usize;

    for f in iter {
        let (lo, hi) = unpack_u32_pair(f);
        block[2 * pos] = lo;
        block[2 * pos + 1] = hi;
        pos += 1;
        count += 1;

        if pos == RATE {
            cv = BlakeG::compress(cv, block);
            block = [0u32; 16];
            pos = 0;
        }
    }

    assert_yielded_len(count, len);

    if count == 0 || pos != 0 {
        cv = BlakeG::compress(cv, block);
    }

    pack_to_word(cv).into()
}

fn hash_u64_iter_with_len<I>(iter: I, len: usize) -> [u64; DIGEST_WIDTH]
where
    I: Iterator<Item = u64>,
{
    let n = u32::try_from(len).expect("input too long: felt count must fit in u32");
    let mut cv = init_cv(0, FELT_MODE, n);
    let mut block = [0u64; RATE];
    let mut pos = 0usize;
    let mut count = 0usize;

    for value in iter {
        block[pos] = value;
        pos += 1;
        count += 1;

        if pos == RATE {
            cv = BlakeG::compress(cv, encode_u64_block(&block));
            block = [0u64; RATE];
            pos = 0;
        }
    }

    assert_yielded_len(count, len);

    if count == 0 || pos != 0 {
        cv = BlakeG::compress(cv, encode_u64_block(&block));
    }

    pack_cv_to_u64s(cv)
}

fn hash_packed_felt_iter_with_len<I>(iter: I, len: usize) -> [[Felt; PACKED_LANES]; DIGEST_WIDTH]
where
    I: Iterator<Item = [Felt; PACKED_LANES]>,
{
    let n = u32::try_from(len).expect("input too long: felt count must fit in u32");
    let mut cv = init_packed_digest(0, FELT_MODE, n);
    let mut block = [[Felt::ZERO; PACKED_LANES]; RATE];
    let mut pos = 0usize;
    let mut count = 0usize;

    for values in iter {
        block[pos] = values;
        pos += 1;
        count += 1;

        if pos == RATE {
            cv = compress_packed_felt_digest_block(cv, block);
            block = [[Felt::ZERO; PACKED_LANES]; RATE];
            pos = 0;
        }
    }

    assert_yielded_len(count, len);

    if count == 0 || pos != 0 {
        cv = compress_packed_felt_digest_block(cv, block);
    }

    cv
}

fn hash_packed_u64_iter_with_len<I>(iter: I, len: usize) -> [[u64; PACKED_LANES]; DIGEST_WIDTH]
where
    I: Iterator<Item = [u64; PACKED_LANES]>,
{
    let n = u32::try_from(len).expect("input too long: felt count must fit in u32");
    let mut cv = init_packed_u64_digest(0, FELT_MODE, n);
    let mut block = [[0; PACKED_LANES]; RATE];
    let mut pos = 0usize;
    let mut count = 0usize;

    for values in iter {
        block[pos] = values;
        pos += 1;
        count += 1;

        if pos == RATE {
            cv = pack_cv_to_packed_u64s(BlakeG::compress_packed_native(
                unpack_packed_u64_digest(cv),
                encode_packed_u64_block(block),
            ));
            block = [[0; PACKED_LANES]; RATE];
            pos = 0;
        }
    }

    assert_yielded_len(count, len);

    if count == 0 || pos != 0 {
        cv = pack_cv_to_packed_u64s(BlakeG::compress_packed_native(
            unpack_packed_u64_digest(cv),
            encode_packed_u64_block(block),
        ));
    }

    cv
}

/// Eidos hash construction.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Eidos;

impl Eidos {
    /// Compress one full felt-mode block under a packed Eidos chaining word.
    #[inline]
    pub fn compress_block(cv: Word, block: [Felt; RATE]) -> Word {
        compress_felt_block(cv, block)
    }

    /// Return BlakeG XOF output for one full felt-mode block.
    ///
    /// Each output element is one canonical `u32` lane embedded in the field.
    /// This is XOF material for callers that already selected the input CV; it
    /// is not an Eidos digest.
    #[inline]
    pub fn compress_xof_block(cv: Word, block: [Felt; RATE]) -> [Felt; 16] {
        let cv = unpack_to_cv(cv);
        let block = encode_felt_block(&block);
        BlakeG::compress_raw_xof(cv, block).map(Felt::from_u32)
    }

    /// Construct the transcript init CV used by the Fiat-Shamir challenger.
    #[inline]
    pub fn transcript_init_cv(selector: u32) -> Word {
        assert!(selector <= MAX_DOMAIN, "selector must fit in 31 bits");

        let mut block = [0u32; 16];
        block[0] = selector;
        pack_to_word(BlakeG::compress([0u32; 8], block))
    }

    /// Construct the felt-mode initial chaining value as a packed digest word.
    #[inline]
    pub fn init_chaining_word(domain: u32, n: u32) -> Word {
        assert!(domain <= MAX_DOMAIN, "domain must fit in 31 bits");
        pack_to_word(init_cv(domain, FELT_MODE, n))
    }

    /// Hash a byte string in byte mode.
    pub fn hash(bytes: &[u8]) -> Word {
        let n = u32::try_from(bytes.len()).expect("input too long: byte count must fit in u32");
        let mut cv = init_cv(0, BYTE_MODE, n);

        if bytes.is_empty() {
            return pack_to_word(BlakeG::compress(cv, [0u32; 16]));
        }

        for chunk in bytes.chunks(64) {
            cv = BlakeG::compress(cv, encode_byte_block(chunk));
        }

        pack_to_word(cv)
    }

    /// Hash field elements in felt mode under domain 0.
    #[inline]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        Self::hash_elements_in_domain(elements, Felt::ZERO)
    }

    /// Hash field elements in felt mode under a user domain.
    pub fn hash_elements_in_domain<E: BasedVectorSpace<Felt>>(
        elements: &[E],
        domain: Felt,
    ) -> Word {
        let domain_u32 = {
            let d = domain.as_canonical_u64();
            assert!(d <= MAX_DOMAIN as u64, "domain must fit in 31 bits");
            d as u32
        };

        let n_total: usize = elements.iter().map(|e| E::as_basis_coefficients_slice(e).len()).sum();
        let n = u32::try_from(n_total).expect("input too long: felt count must fit in u32");
        let mut cv = init_cv(domain_u32, FELT_MODE, n);

        if n == 0 {
            return pack_to_word(BlakeG::compress(cv, [0u32; 16]));
        }

        let mut block = [0u32; 16];
        let mut pos = 0usize;

        for elem in elements {
            for &f in E::as_basis_coefficients_slice(elem) {
                let (lo, hi) = unpack_u32_pair(f);
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

    /// Hash two digest words under domain 0.
    #[inline]
    pub fn merge(values: &[Word; 2]) -> Word {
        Self::merge_in_domain(values, Felt::ZERO)
    }

    /// Hash two digest words under a user domain.
    #[inline]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        let elements: [Felt; RATE] = array::from_fn(|i| values[i / DIGEST_WIDTH][i % DIGEST_WIDTH]);
        Self::hash_elements_in_domain(&elements, domain)
    }

    /// Hash a sequence of digest words under domain 0.
    #[inline]
    pub fn merge_many(values: &[Word]) -> Word {
        Self::hash_elements(Word::words_as_elements(values))
    }
}

impl CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [Felt; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = Felt>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_felt_iter_with_len(iter, len)
        } else {
            let elements: Vec<Felt> = iter.collect();
            Self::hash_elements(&elements).into()
        }
    }
}

impl CryptographicHasher<u64, [u64; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [u64; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = u64>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_u64_iter_with_len(iter, len)
        } else {
            let elements: Vec<u64> = iter.collect();
            let len = elements.len();
            hash_u64_iter_with_len(elements.into_iter(), len)
        }
    }
}

impl CryptographicHasher<[Felt; PACKED_LANES], [[Felt; PACKED_LANES]; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [[Felt; PACKED_LANES]; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = [Felt; PACKED_LANES]>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_packed_felt_iter_with_len(iter, len)
        } else {
            let elements: Vec<[Felt; PACKED_LANES]> = iter.collect();
            let len = elements.len();
            hash_packed_felt_iter_with_len(elements.into_iter(), len)
        }
    }
}

impl CryptographicHasher<[u64; PACKED_LANES], [[u64; PACKED_LANES]; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [[u64; PACKED_LANES]; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = [u64; PACKED_LANES]>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_packed_u64_iter_with_len(iter, len)
        } else {
            let elements: Vec<[u64; PACKED_LANES]> = iter.collect();
            let len = elements.len();
            hash_packed_u64_iter_with_len(elements.into_iter(), len)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_symmetric::CryptographicHasher;

    use super::*;

    struct LooseSizeHint<I>(I);

    impl<I: Iterator> Iterator for LooseSizeHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }

    #[test]
    fn base_constants_match_iv() {
        assert_eq!(BASE0, pack_u32_pair(IV[0], IV[1]).as_canonical_u64());
        assert_eq!(BASE1, pack_u32_pair(IV[2], IV[3]).as_canonical_u64());
        assert_eq!(BASE2, pack_u32_pair(0, IV[5]).as_canonical_u64());
        assert_eq!(BASE3, pack_u32_pair(0, IV[7]).as_canonical_u64());
    }

    #[test]
    fn pack_unpack_roundtrip_in_subspace() {
        let lo = 0x1234_5678u32;
        let hi = 0x4abc_def0u32;
        let f = pack_u32_pair(lo, hi);

        assert_eq!(unpack_u32_pair(f), (lo, hi));
    }

    #[test]
    fn pack_masks_top_bit_of_high_lane() {
        let (_, hi) = unpack_u32_pair(pack_u32_pair(0, 0xffff_ffff));
        assert_eq!(hi, 0x7fff_ffff);
    }

    #[test]
    fn init_cv_layout_for_felt_mode() {
        let cv = init_cv(7, FELT_MODE, 42);
        let expected = Word::new([
            Felt::new_unchecked(BASE0),
            Felt::new_unchecked(BASE1),
            Felt::new_unchecked(BASE2 + 7),
            Felt::new_unchecked(BASE3 + 42),
        ]);

        assert_eq!(cv, unpack_to_cv(expected));
    }

    #[test]
    fn init_cv_layout_for_byte_mode() {
        let cv = init_cv(7, BYTE_MODE, 42);
        let expected = Word::new([
            Felt::new_unchecked(BASE0),
            Felt::new_unchecked(BASE1),
            Felt::new_unchecked(BASE2 + 7 + MODE_BIT as u64),
            Felt::new_unchecked(BASE3 + 42),
        ]);

        assert_eq!(cv, unpack_to_cv(expected));
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
        assert_ne!(Eidos::hash(&[]), Eidos::hash_elements::<Felt>(&[]));
    }

    #[test]
    fn transcript_init_cv_matches_one_blakeg_compression() {
        let selector = 0x0201u32;
        let mut block = [0u32; 16];
        block[0] = selector;

        assert_eq!(
            Eidos::transcript_init_cv(selector),
            pack_to_word(BlakeG::compress([0; 8], block))
        );
    }

    #[test]
    fn compress_xof_block_returns_raw_u32_lanes_as_felts() {
        let cv = Eidos::init_chaining_word(7, RATE as u32);
        let block: [Felt; RATE] = array::from_fn(|idx| Felt::new_unchecked((idx as u64 + 1) * 17));

        let expected = BlakeG::compress_raw_xof(unpack_to_cv(cv), encode_felt_block(&block))
            .map(Felt::from_u32);

        assert_eq!(Eidos::compress_xof_block(cv, block), expected);
    }

    #[test]
    fn packed_felt_hasher_matches_scalar_lanes() {
        let inputs: Vec<[Felt; PACKED_LANES]> = (0..19)
            .map(|i| array::from_fn(|lane| Felt::new_unchecked((i * 17 + lane * 3 + 1) as u64)))
            .collect();
        let packed = <Eidos as CryptographicHasher<
            [Felt; PACKED_LANES],
            [[Felt; PACKED_LANES]; DIGEST_WIDTH],
        >>::hash_iter(&Eidos, inputs.iter().copied());

        for lane in 0..PACKED_LANES {
            let scalar_input: Vec<_> = inputs.iter().map(|value| value[lane]).collect();
            let scalar = <Eidos as CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                scalar_input,
            );
            let packed_lane: [Felt; DIGEST_WIDTH] = array::from_fn(|word| packed[word][lane]);
            assert_eq!(packed_lane, scalar);
        }
    }

    #[test]
    fn u64_hasher_matches_felt_hasher() {
        let inputs: Vec<Felt> =
            (0..19).map(|idx| Felt::new_unchecked((idx * 17 + 1) as u64)).collect();
        let input_words = inputs.iter().map(Felt::as_canonical_u64);

        let packed = <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
            &Eidos,
            input_words,
        );
        let scalar =
            <Eidos as CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]>>::hash_iter(&Eidos, inputs);

        assert_eq!(packed.map(Felt::new_unchecked), scalar);
    }

    #[test]
    fn packed_u64_hasher_matches_scalar_lanes() {
        let inputs: Vec<[u64; PACKED_LANES]> = (0..19)
            .map(|i| {
                array::from_fn(|lane| {
                    Felt::new_unchecked((i * 17 + lane * 3 + 1) as u64).as_canonical_u64()
                })
            })
            .collect();
        let packed = <Eidos as CryptographicHasher<
            [u64; PACKED_LANES],
            [[u64; PACKED_LANES]; DIGEST_WIDTH],
        >>::hash_iter(&Eidos, inputs.iter().copied());

        for lane in 0..PACKED_LANES {
            let scalar_input: Vec<_> = inputs.iter().map(|value| value[lane]).collect();
            let scalar = <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                scalar_input,
            );
            let packed_lane: [u64; DIGEST_WIDTH] = array::from_fn(|word| packed[word][lane]);
            assert_eq!(packed_lane, scalar);
        }
    }

    #[test]
    fn hash_iter_supports_non_exact_iterators() {
        let felts: Vec<Felt> =
            (0..19).map(|idx| Felt::new_unchecked((idx * 17 + 1) as u64)).collect();
        let exact =
            <Eidos as CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]>>::hash_iter(&Eidos, felts);

        let loose = LooseSizeHint((0..19).map(|idx| Felt::new_unchecked((idx * 17 + 1) as u64)));
        let actual =
            <Eidos as CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]>>::hash_iter(&Eidos, loose);

        assert_eq!(actual, exact);
    }

    #[test]
    fn hash_elements_is_deterministic() {
        let xs = vec![Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];
        assert_eq!(Eidos::hash_elements(&xs), Eidos::hash_elements(&xs));
    }
}
