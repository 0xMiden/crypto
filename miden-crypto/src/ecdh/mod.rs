//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

mod k256;
pub use k256::{EphemeralPublicKey, EphemeralSecretKey, SharedSecret};
mod x25519;
pub use x25519::{
    EphemeralPublicKey as X25519EphemeralPublicKey, EphemeralSecretKey as X25519EphemeralSecretKey,
    SharedSecret as X25519SharedSecret,
};
