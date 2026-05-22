//! End-to-end tests for preprocessed traces on the stark-statement API.
//!
//! These exercise the real preprocessed path: the commitment is observed
//! first, the tree is opened via the PCS, and the per-AIR window is fed to the
//! constraint folders. Preprocessed content is served through
//! [`BaseAir::preprocessed_trace`]; the prover bundles it via
//! [`Preprocessed::build`] + [`StarkProverStatement::with_preprocessed`], and
//! the verifier receives only the commitment via
//! [`StarkStatement::with_preprocessed`].

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Preprocessed, PreprocessedValidationError, StarkProverStatement, StarkStatement,
    air::{
        AirBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder, MultiAir,
        ProverStatement, Statement, WindowAccess,
    },
    prove,
    testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, test_challenger, test_config},
    verify,
};

// ---------------------------------------------------------------------------
// AIR fixtures
// ---------------------------------------------------------------------------

/// AIR with a preprocessed column carrying the row index `0, 1, 2, …`, served
/// by value through [`BaseAir::preprocessed_trace`].
///
/// Constraints (gated so symbolic degree ≥ 2): first row `main[0] ==
/// preprocessed[0]`; transition `Δmain == Δpreprocessed` (uses the
/// preprocessed window non-trivially); first row `aux[0] == challenge`.
#[derive(Clone, Debug)]
struct RowCounterAir {
    preprocessed: RowMajorMatrix<Felt>,
}

impl BaseAir<Felt> for RowCounterAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }
}

impl LiftedAir<Felt, QuadFelt> for RowCounterAir {
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let local_main: AB::Expr = main.current_slice()[0].into();
        let next_main: AB::Expr = main.next_slice()[0].into();

        let preproc = builder.preprocessed();
        let local_preproc: AB::Expr = preproc.current_slice()[0].into();
        let next_preproc: AB::Expr = preproc.next_slice()[0].into();

        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();

        builder.when_first_row().assert_eq(local_main.clone(), local_preproc.clone());
        builder
            .when_transition()
            .assert_eq(next_main - local_main, next_preproc - local_preproc);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
    }
}

/// AIR with no preprocessed columns. Transition `next == local²`.
#[derive(Clone, Copy, Debug)]
struct ConstantAir;

impl BaseAir<Felt> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
}

impl LiftedAir<Felt, QuadFelt> for ConstantAir {
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let local: AB::Expr = main.current_slice()[0].into();
        let next: AB::Expr = main.next_slice()[0].into();

        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();

        builder.when_transition().assert_eq(next, local.clone() * local);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
    }
}

/// Heterogeneous AIR for mixed-instance tests.
#[derive(Clone, Debug)]
enum MixedAir {
    Constant(ConstantAir),
    RowCounter(RowCounterAir),
}

impl BaseAir<Felt> for MixedAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::Constant(_) => None,
            Self::RowCounter(a) => a.preprocessed_trace(),
        }
    }
}

impl LiftedAir<Felt, QuadFelt> for MixedAir {
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Constant(_) => 0,
            Self::RowCounter(a) => a.preprocessed_width(),
        }
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        match self {
            Self::Constant(a) => a.build_aux_trace(main, air_inputs, aux_inputs, challenges),
            Self::RowCounter(a) => a.build_aux_trace(main, air_inputs, aux_inputs, challenges),
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Constant(a) => a.eval(builder),
            Self::RowCounter(a) => a.eval(builder),
        }
    }
}

/// AIR that declares a wider preprocessed trace (`preprocessed_width() == 2`)
/// than the matrix it serves (width 1), to drive the width-mismatch check.
#[derive(Clone, Debug)]
struct WrongWidthAir {
    preprocessed: RowMajorMatrix<Felt>,
}

impl BaseAir<Felt> for WrongWidthAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }
}

impl LiftedAir<Felt, QuadFelt> for WrongWidthAir {
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Well-formed degree-2 constraint; never reached because validation
        // rejects the bundle before proving.
        let main = builder.main();
        let local: AB::Expr = main.current_slice()[0].into();
        let next: AB::Expr = main.next_slice()[0].into();
        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();
        builder.when_transition().assert_eq(next, local.clone() * local);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
    }
}

// ---------------------------------------------------------------------------
// MultiAir + helpers
// ---------------------------------------------------------------------------

/// Minimal [`MultiAir`] over a homogeneous AIR list.
#[derive(Clone, Debug)]
struct PreprocMultiAir<A> {
    airs: Vec<A>,
}

impl<A: LiftedAir<Felt, QuadFelt>> MultiAir<Felt, QuadFelt> for PreprocMultiAir<A> {
    type Air = A;

    fn airs(&self) -> &[A] {
        &self.airs
    }
}

fn row_index_trace(height: usize) -> RowMajorMatrix<Felt> {
    RowMajorMatrix::new((0..height).map(|r| Felt::from_u64(r as u64)).collect(), 1)
}

/// Trace satisfying [`ConstantAir`]'s `next == local²` transition.
fn squaring_trace(height: usize) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(height);
    let mut current = Felt::from_u64(2);
    for _ in 0..height {
        values.push(current);
        current = current * current;
    }
    RowMajorMatrix::new(values, 1)
}

/// Constant aux trace `[challenge; height]`, matching every fixture AIR.
fn build_aux(height: usize, challenges: &[QuadFelt]) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    (RowMajorMatrix::new(vec![challenges[0]; height], 1), Vec::new())
}

/// Build a no-public-input prover statement for `airs` + `traces`.
fn prover_statement<A: LiftedAir<Felt, QuadFelt>>(
    airs: Vec<A>,
    traces: Vec<RowMajorMatrix<Felt>>,
) -> ProverStatement<Felt, QuadFelt, PreprocMultiAir<A>> {
    let statement = Statement::new(PreprocMultiAir { airs }, vec![], vec![]).expect("statement");
    ProverStatement::new(statement, traces).expect("prover statement")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn single_air_with_preprocessed() {
    let height = 8;
    let ps = prover_statement(
        vec![RowCounterAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let sps = StarkProverStatement::with_preprocessed(&config, &ps, &preprocessed).expect("valid");
    let output = prove(&sps, test_challenger()).expect("prove succeeds");

    let ss = StarkStatement::with_preprocessed(&config, ps.statement(), preprocessed.commitment())
        .expect("valid");
    let digest = verify(&ss, &output.proof, test_challenger()).expect("verify succeeds");
    assert_eq!(output.digest, digest);
}

#[test]
fn mixed_airs_preprocessed_at_index_1() {
    let height = 8;
    let ps = prover_statement(
        vec![
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(height) }),
        ],
        vec![squaring_trace(height), row_index_trace(height)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let sps = StarkProverStatement::with_preprocessed(&config, &ps, &preprocessed).expect("valid");
    let output = prove(&sps, test_challenger()).expect("prove succeeds");

    let ss = StarkStatement::with_preprocessed(&config, ps.statement(), preprocessed.commitment())
        .expect("valid");
    let digest = verify(&ss, &output.proof, test_challenger()).expect("verify succeeds");
    assert_eq!(output.digest, digest);
}

#[test]
fn rejects_width_mismatch() {
    let height = 8;
    let ps = prover_statement(
        vec![WrongWidthAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let result = StarkProverStatement::with_preprocessed(&config, &ps, &preprocessed);
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::WidthMismatch { expected: 2, actual: 1, .. })
        ),
        "expected WidthMismatch {{ expected: 2, actual: 1 }}",
    );
}

#[test]
fn rejects_height_mismatch() {
    // Preprocessed matrix height (4) differs from the main trace height (8).
    let ps = prover_statement(
        vec![RowCounterAir { preprocessed: row_index_trace(4) }],
        vec![row_index_trace(8)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let result = StarkProverStatement::with_preprocessed(&config, &ps, &preprocessed);
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::HeightMismatch { main: 8, preprocessed: 4, .. })
        ),
        "expected HeightMismatch {{ main: 8, preprocessed: 4 }}",
    );
}

#[test]
fn rejects_max_height_below_max_trace() {
    // The tallest AIR (ConstantAir, height 8) has no preprocessed trace, so the
    // preprocessed tree's tallest leaf (RowCounter, height 4) sits below the
    // max trace height — rejected by the PCS equal-height restriction.
    let ps = prover_statement(
        vec![
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(4) }),
        ],
        vec![squaring_trace(8), row_index_trace(4)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let result = StarkProverStatement::with_preprocessed(&config, &ps, &preprocessed);
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::MaxHeightBelowMaxTrace {
                preprocessed: 4,
                max_trace: 8
            })
        ),
        "expected MaxHeightBelowMaxTrace {{ preprocessed: 4, max_trace: 8 }}",
    );
}
