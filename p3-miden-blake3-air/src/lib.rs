//! Blake3 **compression** AIR (Plonky3-style) with a narrower output witness: six 32-bit words
//! (192 bits) instead of sixteen.

#![no_std]

extern crate alloc;

mod air;
mod columns;
mod constants;
mod generation;

pub use air::Blake3_192Air;
pub use columns::{Blake3_192Cols, Blake3State, FullRound, NUM_BLAKE3_192_COLS};
pub use generation::generate_trace_rows;
