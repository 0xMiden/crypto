//! Integrated Encryption Scheme (IES) utilities.
//!
//! This module combines elliptic-curve Diffie–Hellman (ECDH) key agreement with authenticated
//! encryption (AEAD) to provide sealed boxes that offer confidentiality and integrity for messages.
//! It exposes a simple API via [`SealingKey`], [`UnsealingKey`], [`SealedMessage`], and
//! [`IesError`].
//!
//! # Examples
//!
//! ```
//! use miden_crypto::{
//!     dsa::eddsa_25519::SecretKey,
//!     ies::{SealingKey, UnsealingKey},
//! };
//! use rand::rng;
//!
//! let mut rng = rng();
//! let secret_key = SecretKey::with_rng(&mut rng);
//! let public_key = secret_key.public_key();
//!
//! let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
//! let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
//!
//! let sealed = sealing_key.seal(&mut rng, b"hello world").unwrap();
//! let opened = unsealing_key.unseal(sealed).unwrap();
//!
//! assert_eq!(opened.as_slice(), b"hello world");
//! ```

mod crypto_box;
mod error;
mod keys;
mod message;

#[cfg(test)]
mod tests;

pub use error::IesError;
pub use keys::{SealingKey, UnsealingKey};
pub use message::SealedMessage;
