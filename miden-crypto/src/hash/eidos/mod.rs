//! Eidos hash function built on BlakeG compression.
//!
//! This variant finalizes each BlakeG output pair by reducing a 64-bit word
//! modulo the Goldilocks prime. If the raw pair is modeled as uniform, one Felt
//! has statistical distance (TVD) about `2^-32` from uniform and at most 63 bits
//! of min-entropy.

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
