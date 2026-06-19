//! Eidos hash function built on BlakeG compression.

pub mod aead_ref;
mod challenger;
mod framing;
mod lmcs;
mod primitive;

#[cfg(test)]
mod tests;

pub use challenger::{EidosChallenger, MidenEidosChallenger};
pub use framing::{DIGEST_WIDTH, Eidos, RATE};
pub use lmcs::{EidosLmcs, config as lmcs_config};

#[cfg(feature = "internal")]
#[doc(hidden)]
pub use primitive::bench;
