//! Wrappers around fn-dsa code we vendor locally.
//! This groups the upstream FLR sampler and NTRU/keygen helpers.

pub(crate) mod flr;
pub(crate) mod keygen;

// Re-export fn-dsa keygen entrypoint.
pub(crate) use keygen::ntru_gen;
