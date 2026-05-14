//! Eidos hash function: BlakeG (field-layer primitive) + Eidos (VM-layer hash).
//!
//! See `SPEC.md` in this directory for the full design specification, including
//! security claims, design rationale, and future AEAD direction.
//!
//! # Two-stream architecture
//!
//! - [`BlakeG`] (Stream 1): Goldilocks-tailored BLAKE3 compression function. Field-layer
//!   primitive with no Miden VM dependencies. Suitable for any Goldilocks project.
//! - [`Eidos`] (Stream 2): VM-layer hash function built on BlakeG. Owns padding, domain
//!   separation, mode bits, and the public API. Mirrors the Poseidon2 surface.
//!
//! # Security target
//!
//! - 126-bit collision resistance.
//! - 252-bit preimage resistance.
//!
//! See SPEC §5 for the derivation. The 2-bit gap below the BLAKE3-standard 128-bit
//! collision target is purely a Goldilocks felt-packing artifact.

pub mod framing;
pub mod primitive;

#[cfg(test)]
mod tests;

pub use framing::{DIGEST_WIDTH, Eidos, RATE};
pub use primitive::BlakeG;
