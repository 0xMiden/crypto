use alloc::vec::Vec;
use num::Integer;

use core::{fmt, ops::Range};

use rand::{
    Rng,
    distr::{Distribution, StandardUniform, Uniform},
};

use crate::{Felt, ONE, StarkField, ZERO, hash::rpo::Rpo256};

#[cfg(test)]
mod test;

// CONSTANTS
// ================================================================================================

/// Size of a secret key in field elements
pub const SECRET_KEY_SIZE: usize = 4;

/// Size of a nonce in field elements
pub const NONCE_SIZE: usize = 4;

/// Size of an authentication tag in field elements
pub const AUTH_TAG_SIZE: usize = 4;

/// Size of the sponge state field elements
const STATE_WIDTH: usize = Rpo256::STATE_WIDTH;

/// Rate portion of the sponge state
const RATE_RANGE: Range<usize> = Rpo256::RATE_RANGE;

/// Size of the rate portion of the sponge state in field elements
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

/// Size of either the 1st or 2nd half of the rate portion of the sponge state in field elements
const HALF_RATE_WIDTH: usize = (Rpo256::RATE_RANGE.end - Rpo256::RATE_RANGE.start) / 2;

/// First half of the rate portion of the sponge state
const RATE_RANGE_FIRST_HALF: Range<usize> =
    Rpo256::RATE_RANGE.start..Rpo256::RATE_RANGE.start + HALF_RATE_WIDTH;

/// Second half of the rate portion of the sponge state
const RATE_RANGE_SECOND_HALF: Range<usize> =
    Rpo256::RATE_RANGE.start + HALF_RATE_WIDTH..Rpo256::RATE_RANGE.end;

/// Index of the first element of the rate portion of the sponge state
const RATE_START: usize = Rpo256::RATE_RANGE.start;

/// Padding block used when the length of the data to encrypt is a multiple of `RATE_WIDTH`
const PADDING_BLOCK: [Felt; RATE_WIDTH] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

// TYPES AND STRUCTURES
// ================================================================================================

/// A 256-bit secret key represented as 4 field elements
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey([Felt; SECRET_KEY_SIZE]);

/// A 256-bit nonce represented as 4 field elements
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([Felt; NONCE_SIZE]);

/// An authentication tag represented as 4 field elements
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthTag([Felt; AUTH_TAG_SIZE]);

/// Encrypted data with its authentication tag
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// The associated data
    pub associated_data: Vec<Felt>,
    /// The encrypted ciphertext
    pub ciphertext: Vec<Felt>,
    /// The authentication tag
    pub auth_tag: AuthTag,
}

/// Internal sponge state
struct SpongeState {
    state: [Felt; STATE_WIDTH],
}

impl SpongeState {
    /// Creates a new sponge state
    fn new() -> Self {
        Self { state: [ZERO; STATE_WIDTH] }
    }

    /// Duplex interface as described in Algorithm 2 in [1] with `d = 0`
    ///
    ///
    /// [1]: https://eprint.iacr.org/2023/1668
    fn duplex_overwrite(&mut self, data: &[Felt]) {
        self.permute();

        let _ = self.squeeze_rate();

        for (idx, &element) in data.iter().enumerate() {
            self.state[RATE_START + idx] = element;
        }
    }

    /// Duplex interface as described in Algorithm 2 in [1] with `d = 1`
    ///
    ///
    /// [1]: https://eprint.iacr.org/2023/1668
    fn duplex_add(&mut self, data: &[Felt]) -> [Felt; RATE_WIDTH] {
        self.permute();

        let squeezed_data = self.squeeze_rate();

        for (idx, &element) in data.iter().enumerate() {
            self.state[RATE_START + idx] += element;
        }

        squeezed_data
    }

    /// Squeezes an authentication tag
    fn squeeze_tag(&mut self) -> AuthTag {
        self.permute();
        AuthTag(
            self.state[RATE_RANGE_FIRST_HALF]
                .try_into()
                .expect("failed to convert to array"),
        )
    }

    /// Applies the RPO permutation to the sponge state
    fn permute(&mut self) {
        Rpo256::apply_permutation(&mut self.state);
    }

    fn initialize(&mut self, sk: &SecretKey, nonce: &Nonce) {
        self.state[RATE_RANGE_FIRST_HALF].copy_from_slice(&sk.0);
        self.state[RATE_RANGE_SECOND_HALF].copy_from_slice(&nonce.0);
    }

    fn squeeze_rate(&self) -> [Felt; RATE_WIDTH] {
        self.state[RATE_RANGE].try_into().unwrap()
    }
}

// SECRET KEY IMPLEMENTATION
// ================================================================================================

impl SecretKey {
    /// Creates a new random secret key using the default random number generator
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::from_os_rng();

        Self::with_rng(&mut rng)
    }

    /// Creates a new random secret key using the provided random number generator
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
    }

    /// Encrypts the provided data using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt(&self, data: &[Felt], associated_data: &[Felt]) -> EncryptedData {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::from_os_rng();
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_with_nonce(data, associated_data, &nonce)
    }

    /// Encrypts the provided data using this secret key and a specified nonce
    pub fn encrypt_with_nonce(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
        nonce: &Nonce,
    ) -> EncryptedData {
        if data.is_empty() {
            return EncryptedData::default();
        }
        let mut sponge = SpongeState::new();

        // Initialize with key and nonce
        sponge.initialize(&self, nonce);

        // Process the associated data
        let padded_associated_data = pad_associated_data(associated_data);
        padded_associated_data.chunks(RATE_WIDTH).for_each(|chunk| {
            sponge.duplex_overwrite(chunk);
        });

        // Encrypt the data
        let mut ciphertext = Vec::with_capacity(data.len());
        let mut data_block_iterator = data.chunks_exact(RATE_WIDTH);

        data_block_iterator.by_ref().for_each(|data_block| {
            let keystream = sponge.duplex_add(data_block);
            for (i, &plaintext_felt) in data_block.iter().enumerate() {
                ciphertext.push(plaintext_felt + keystream[i]);
            }
        });

        // Finalize and generate authentication tag
        let final_uneven_block = data_block_iterator.remainder();
        let final_uneven_ciphertext_block = finalize_encryption(&mut sponge, final_uneven_block);
        ciphertext.extend_from_slice(&final_uneven_ciphertext_block);

        let auth_tag = sponge.squeeze_tag();

        EncryptedData {
            ciphertext,
            associated_data: associated_data.into(),
            auth_tag,
        }
    }

    /// Decrypts the provided encrypted data using this secret key
    pub fn decrypt(
        &self,
        encrypted_data: &EncryptedData,
        nonce: &Nonce,
    ) -> Result<Vec<Felt>, EncryptionError> {
        assert_eq!(encrypted_data.ciphertext.len() % RATE_WIDTH, 0);

        if encrypted_data.ciphertext.is_empty() {
            return Ok(vec![]);
        }

        let mut sponge = SpongeState::new();

        // Initialize with key and nonce (same as encryption)
        sponge.initialize(self, nonce);

        // Process the associated data
        let padded_associated_data = pad_associated_data(&encrypted_data.associated_data);
        padded_associated_data.chunks(RATE_WIDTH).for_each(|chunk| {
            sponge.duplex_overwrite(chunk);
        });

        // Decrypt the data
        let mut plaintext = Vec::with_capacity(encrypted_data.ciphertext.len());
        let mut ciphertext_block_iterator = encrypted_data.ciphertext.chunks_exact(RATE_WIDTH);
        ciphertext_block_iterator.by_ref().for_each(|ciphertext_data_block| {
            let keystream = sponge.duplex_add(&[]);
            for (i, &ciphertext_felt) in ciphertext_data_block.iter().enumerate() {
                let plaintext_felt = ciphertext_felt - keystream[i];
                plaintext.push(plaintext_felt);
            }
            sponge.state[RATE_RANGE].copy_from_slice(&ciphertext_data_block);
        });

        // Verify authentication tag
        let computed_tag = sponge.squeeze_tag();
        if computed_tag != encrypted_data.auth_tag {
            return Err(EncryptionError::InvalidAuthTag);
        }

        // Remove padding
        unpad(&mut plaintext);

        Ok(plaintext)
    }
}

/// Pads the associated data.
fn pad_associated_data(associated_data: &[Felt]) -> Vec<Felt> {
    if associated_data.len() % RATE_WIDTH == 0 {
        return associated_data.to_vec();
    } else {
        let mut result = associated_data.to_vec();

        while result.len() % RATE_WIDTH != 0 {
            result.push(ZERO)
        }
        return result;
    }
}

/// Finalizes encryption by performing the padding and encryption of the final block.
fn finalize_encryption(sponge: &mut SpongeState, remaining_data: &[Felt]) -> Vec<Felt> {
    let mut ciphertext = Vec::with_capacity(RATE_WIDTH);

    if remaining_data.len() == 0 {
        let keystream = sponge.duplex_add(&PADDING_BLOCK);
        for (i, &plaintext_felt) in PADDING_BLOCK.iter().enumerate() {
            ciphertext.push(plaintext_felt + keystream[i]);
        }
    } else {
        debug_assert!(1 <= remaining_data.len() && remaining_data.len() < RATE_WIDTH);
        let mut chunk = [ZERO; RATE_WIDTH];
        remaining_data.iter().enumerate().for_each(|(idx, entry)| chunk[idx] = *entry);
        chunk[remaining_data.len()] = ONE;

        for i in (remaining_data.len() + 1)..RATE_WIDTH {
            chunk[i] = ZERO
        }
        let keystream = sponge.duplex_add(&chunk);
        for (i, &plaintext_felt) in chunk.iter().enumerate() {
            ciphertext.push(plaintext_felt + keystream[i]);
        }
    }

    ciphertext
}

/// Removes the padding from the decoded ciphertext.
fn unpad(plaintext: &mut Vec<Felt>) {
    let (num_blocks, remainder) = plaintext.len().div_rem(&RATE_WIDTH);
    assert_eq!(remainder, 0);

    let final_block: &[Felt; RATE_WIDTH] = plaintext.last_chunk().expect("plaintext is empty");

    let position = final_block
        .iter()
        .rposition(|entry| *entry == ONE)
        .expect("padding with ONE is missing");

    plaintext.truncate((num_blocks - 1) * RATE_WIDTH + position);
}

impl Distribution<SecretKey> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        let mut res = [ZERO; SECRET_KEY_SIZE];
        let uni_dist =
            Uniform::new(0, Felt::MODULUS).expect("should not fail given the size of the field");
        for r in res.iter_mut() {
            let sampled_integer = uni_dist.sample(rng);
            *r = Felt::new(sampled_integer);
        }
        SecretKey(res)
    }
}

// NONCE IMPLEMENTATION
// ================================================================================================

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
    }
}

impl Distribution<Nonce> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Nonce {
        let mut res = [ZERO; NONCE_SIZE];
        let uni_dist =
            Uniform::new(0, Felt::MODULUS).expect("should not fail given the size of the field");
        for r in res.iter_mut() {
            let sampled_integer = uni_dist.sample(rng);
            *r = Felt::new(sampled_integer);
        }
        Nonce(res)
    }
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionError {
    /// Authentication tag verification failed
    InvalidAuthTag,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InvalidAuthTag => write!(f, "Authentication tag verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncryptionError {}
