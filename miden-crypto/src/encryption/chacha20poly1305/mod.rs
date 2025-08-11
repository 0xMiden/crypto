use crate::Felt;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};

/// A 256-bit secret key represented as 4 field elements
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Creates a new random secret key using the default random number generator
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::from_os_rng();
        Self::with_rng(&mut rng)
    }

    /// Creates a new random secret key using the provided random number generator
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        let key = Aes256Gcm::generate_key(rng);
        Self(key.into())
    }

    /// Encrypts the provided data, as Felt-s, using this secret key and a random nonce
    #[cfg(feature = "std")]
    pub fn encrypt(&self, data: &[Felt], associated_data: &[Felt]) -> EncryptedData {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::from_os_rng();
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_with_nonce(data, associated_data, &nonce)
    }
}
