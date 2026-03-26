//! Example AIRs wrapped for the lifted STARK prover.
//!
//! Each module adapts an upstream Plonky3 AIR into a `LiftedAir` so it can be proven
//! and verified with the lifted STARK protocol.

#![no_std]

extern crate alloc;

use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
extern crate std;

pub mod blake3;
pub mod keccak;
pub mod miden;
pub mod poseidon2;

#[cfg(feature = "std")]
pub mod stats;

use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_miden_lifted_air::AuxBuilder;

/// Dummy aux builder that produces a 1-column all-zero auxiliary trace.
///
/// Used for AIRs without meaningful auxiliary columns. Every `LiftedAir`
/// must have at least one aux column, so this builder satisfies the
/// requirement with minimal cost. Returns no aux values.
pub struct DummyAuxBuilder;

impl<F: Field, EF: ExtensionField<F>> AuxBuilder<F, EF> for DummyAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let height = main.height();
        let aux_trace = RowMajorMatrix::new(EF::zero_vec(height), 1);
        (aux_trace, vec![])
    }
}
