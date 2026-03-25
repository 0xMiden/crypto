extern crate alloc;

mod common;

use alloc::vec::Vec;

use common::test_config;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_miden_dev_utils::configs::goldilocks_poseidon2::{EF, F, test_challenger};
use p3_miden_lifted_stark::{
    air::{AuxBuilder, BaseAir, LiftedAir, LiftedAirBuilder},
    prover::prove_single,
};

#[derive(Clone, Copy, Debug)]
struct BadAuxWidthAir;

impl BaseAir<F> for BadAuxWidthAir {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<F, EF> for BadAuxWidthAir {
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

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, _builder: &mut AB) {}
}

/// AuxBuilder that returns 2 EF columns when BadAuxWidthAir declares 1.
struct BadAuxBuilder;

impl AuxBuilder<F, EF> for BadAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let height = main.height();
        // Return 2 EF columns when aux_width() declares 1
        let aux = RowMajorMatrix::new(vec![EF::ZERO; height * 2], 2);
        (aux, vec![EF::ZERO, EF::ZERO])
    }
}

#[test]
#[should_panic(expected = "aux trace width mismatch")]
fn aux_width_mismatch_panics() {
    let config = test_config();
    let air = BadAuxWidthAir;

    let trace = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::ONE, F::ZERO], 1);
    let public_values = vec![];

    let _result = prove_single(
        &config,
        &air,
        &trace,
        &public_values,
        &[],
        &BadAuxBuilder,
        test_challenger(),
    );
}
