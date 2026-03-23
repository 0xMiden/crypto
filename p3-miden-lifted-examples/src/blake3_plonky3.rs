//! Plonky3 [`p3_blake3_air::Blake3Air`] as a [`LiftedAir`] (full compression output witness).

use alloc::vec::Vec;

use p3_blake3_air::Blake3Air;
pub use p3_blake3_air::NUM_BLAKE3_COLS;
use p3_field::{Field, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_miden_lifted_air::{Air, BaseAir, LiftedAir, LiftedAirBuilder};

/// Full-width Blake3 compression AIR from `p3-blake3-air`.
pub struct LiftedPlonky3Blake3Air;

impl Default for LiftedPlonky3Blake3Air {
    fn default() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for LiftedPlonky3Blake3Air {
    fn width(&self) -> usize {
        NUM_BLAKE3_COLS
    }
}

impl<F: PrimeField64, EF: Field> LiftedAir<F, EF> for LiftedPlonky3Blake3Air {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        Air::eval(&Blake3Air {}, builder);
    }
}

/// Trace for [`Blake3Air`] (same layout as `p3_blake3_air::generate_trace_rows`).
pub fn generate_plonky3_blake3_trace<F: PrimeField64>(inputs: Vec<[u32; 24]>) -> RowMajorMatrix<F> {
    p3_blake3_air::generate_trace_rows(inputs, 0)
}
