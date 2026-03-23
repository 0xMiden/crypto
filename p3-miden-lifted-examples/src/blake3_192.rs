//! Aliases for [`crate::blake3`] (Blake3 compression with 192-bit output witness).

pub use p3_miden_blake3_air::NUM_BLAKE3_192_COLS;

pub use crate::blake3::{
    LiftedBlake3Air as LiftedBlake3_192Air, generate_blake3_trace as generate_blake3_192_trace,
};
