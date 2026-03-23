//! BLAKE3 with a **192-bit** (24-byte) digest for Plonky3 / p3-miden.
//!
//! [`Blake3_192`] exposes ~96-bit collision resistance in the Merkle-tree setting,
//! matching Miden VM’s 96-bit STARK target and Winterfell’s `Blake3_192` pattern
//! (full BLAKE3, truncate the 32-byte output to 24 bytes).

#![no_std]

use p3_symmetric::CryptographicHasher;
use p3_util::apply_to_chunks;

/// BLAKE3 with **192-bit** output (24 bytes).
///
/// Collision resistance is approximately **96 bits** in the hash-tree setting. The
/// implementation hashes with standard BLAKE3 and keeps the first 24 bytes of the
/// 32-byte output (same as Winterfell’s `Blake3_192`).
#[derive(Copy, Clone, Debug, Default)]
pub struct Blake3_192;

#[inline]
fn truncate_24(full: [u8; 32]) -> [u8; 24] {
    core::array::from_fn(|i| full[i])
}

impl CryptographicHasher<u8, [u8; 24]> for Blake3_192 {
    fn hash_iter<I>(&self, input: I) -> [u8; 24]
    where
        I: IntoIterator<Item = u8>,
    {
        const BUFLEN: usize = 512;
        let mut hasher = blake3::Hasher::new();
        apply_to_chunks::<BUFLEN, _, _>(input, |buf| {
            hasher.update(buf);
        });
        truncate_24(hasher.finalize().into())
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 24]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = blake3::Hasher::new();
        for chunk in input {
            hasher.update(chunk);
        }
        truncate_24(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use p3_symmetric::CryptographicHasher;

    use super::Blake3_192;

    #[test]
    fn digest_is_prefix_of_full_blake3() {
        let data = b"p3-miden BLAKE3-192";
        let full: [u8; 32] = blake3::hash(data).into();
        let short = Blake3_192.hash_iter(data.iter().copied());
        assert_eq!(short, core::array::from_fn(|i| full[i]));
    }
}
