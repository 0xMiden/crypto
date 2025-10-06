//! Integrated Encryption Scheme (IES) module.
//!
//! This module provides high-level authenticated encryption built from combining elliptic-curve
//! Diffie–Hellman (ECDH) for key agreement with an authenticated encryption with associated data
//! scheme for message encryption.
//!
//! The implementation is split across four submodules:
//! - [`crypto_box`] - Core `CryptoBox` primitive & raw message format
//! - [`keys`] - Public/private key wrappers and sealing/unsealing API
//! - [`message`] - Sealed message format and algorithm identifiers
//! - [`error`] - Error types for IES operations

mod crypto_box;
mod error;
mod keys;
mod message;

#[cfg(test)]
mod tests;

pub use error::IntegratedEncryptionSchemeError;
pub use keys::{SealingKey, UnsealingKey};
pub use message::SealedMessage;
