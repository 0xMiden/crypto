//! Stark-layer statement wrappers that bundle a [`StarkConfig`] with the
//! air-crate [`Statement`] / [`ProverStatement`] and the optional preprocessed
//! data.
//!
//! Preprocessed columns are *fixed circuit data* (lookup tables, selectors)
//! declared by the AIR via [`BaseAir::preprocessed_trace`] and committed once
//! at setup. The prover side ([`StarkProverStatement`]) holds the cached raw
//! matrices plus their LDE tree (the [`Preprocessed`] bundle, built once and
//! borrowed across proofs); the verifier side ([`StarkStatement`]) holds only
//! the commitment (a root hash, trusted like the AIR list itself).
//!
//! Each side has two constructors: `new` (no preprocessed — asserts every AIR
//! has `preprocessed_width() == 0`) and `with_preprocessed` (asserts at least
//! one AIR declares preprocessed columns, and on the prover side validates the
//! bundle against the AIRs). Holding either wrapper is a guarantee its
//! preprocessed shape is consistent, so [`prove`](crate::prove) /
//! [`verify`](crate::verify) never re-check it.

use alloc::vec::Vec;

use miden_lifted_air::{BaseAir, LiftedAir, MultiAir, ProverStatement, Statement, log2_strict_u8};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;
use tracing::info_span;

use crate::{
    StarkConfig,
    domain::LiftedDomain,
    lmcs::{Lmcs, LmcsTree},
    order::TraceOrder,
    prover::commit::Committed,
    util::bitrev::materialize_bitrev,
};

// ============================================================================
// Preprocessed
// ============================================================================

/// Fixed per-AIR preprocessed data: the cached raw matrices plus their
/// committed LDE tree.
///
/// `traces[i]` is `Some` exactly when AIR `i` declares preprocessed columns;
/// the LDE tree commits one leaf per such AIR, in proof (leaf) order. Built
/// once at setup via [`Preprocessed::build`] and borrowed across proofs.
///
/// Parameterized over the LMCS `L` rather than a full [`StarkConfig`] because
/// the bundle depends only on the base field and the commitment scheme.
pub struct Preprocessed<F, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Per-AIR raw preprocessed matrices in instance order; `None` where the
    /// AIR declares none. The cached [`BaseAir::preprocessed_trace`] evals —
    /// `preprocessed_trace` re-allocates on every call, so they are computed
    /// once here and retained for validation and `check_constraints`.
    traces: Vec<Option<RowMajorMatrix<F>>>,
    /// Committed LDE tree, one leaf per preprocessed AIR.
    committed: Committed<F, RowMajorMatrix<F>, L>,
}

impl<F, L> Preprocessed<F, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Build the preprocessed bundle from a statement's AIRs, or `None` when no
    /// AIR declares preprocessed columns.
    ///
    /// Calls [`BaseAir::preprocessed_trace`] once per AIR (caching the by-value
    /// result), then LDEs the declared matrices — sorted height-ascending,
    /// tiebroken by AIR index, the LMCS leaf order both sides reproduce — and
    /// builds the aligned tree.
    ///
    /// # Panics
    ///
    /// Panics if a declared preprocessed matrix has non-power-of-two height or
    /// its LDE order exceeds the field's two-adicity — programmer errors at
    /// setup, not untrusted input.
    pub fn build<EF, MA, C>(statement: &Statement<F, EF, MA>, config: &C) -> Option<Self>
    where
        EF: ExtensionField<F>,
        MA: MultiAir<F, EF>,
        C: StarkConfig<F, EF, Lmcs = L>,
    {
        let traces: Vec<Option<RowMajorMatrix<F>>> =
            statement.airs().iter().map(|a| a.preprocessed_trace()).collect();
        if traces.iter().all(Option::is_none) {
            return None;
        }

        let mut pairs: Vec<(usize, &RowMajorMatrix<F>)> = traces
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.as_ref().map(|m| (i, m)))
            .collect();
        pairs.sort_by_key(|(air_idx, m)| (m.height(), *air_idx));

        let log_blowup = config.pcs().log_blowup();
        let ldes: Vec<_> = pairs
            .into_iter()
            .map(|(air_idx, trace)| {
                let height = trace.height();
                assert!(
                    height.is_power_of_two(),
                    "preprocessed matrix for AIR {air_idx} has non-power-of-two height {height}",
                );
                let log_h = log2_strict_u8(height);
                let coset_shift = LiftedDomain::<F>::canonical_lde_shift(log_h + log_blowup)
                    .expect("preprocessed LDE order exceeds field two-adicity");
                let width = trace.width();
                info_span!("preprocessed LDE", air = air_idx, log_height = log_h, width).in_scope(
                    || {
                        let lde = config.dft().coset_lde_batch(
                            trace.clone(),
                            log_blowup.into(),
                            coset_shift,
                        );
                        materialize_bitrev(lde)
                    },
                )
            })
            .collect();

        Some(Self {
            traces,
            committed: Committed::new(config.lmcs().build_aligned_tree(ldes)),
        })
    }

    /// Commitment (Merkle root) of the preprocessed LDE tree — handed to the
    /// verifier via [`StarkStatement::with_preprocessed`].
    pub fn commitment(&self) -> L::Commitment {
        self.committed.root()
    }

    /// The committed LDE tree, for opening and per-AIR quotient-domain views.
    pub(crate) fn committed(&self) -> &Committed<F, RowMajorMatrix<F>, L> {
        &self.committed
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate a [`Preprocessed`] bundle against a prover statement's AIRs: tree
/// presence, per-leaf width, per-AIR height, and the PCS max-height invariant.
fn validate_preprocessed<F, EF, MA, L>(
    prover_statement: &ProverStatement<F, EF, MA>,
    preprocessed: &Preprocessed<F, L>,
) -> Result<(), PreprocessedValidationError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    L: Lmcs<F = F>,
{
    let airs = prover_statement.statement().airs();
    let main_traces = prover_statement.traces();

    if !airs.iter().any(|a| a.preprocessed_width() > 0) {
        return Err(PreprocessedValidationError::TreeUnexpected);
    }

    // Reconstruct the leaf↔AIR mapping the prover/verifier use. Heights are
    // already validated by `ProverStatement::new`, so this cannot fail.
    let heights: Vec<usize> = main_traces.iter().map(Matrix::height).collect();
    let trace_order = TraceOrder::from_trace_heights::<F, EF, _>(airs, &heights)
        .expect("ProverStatement guarantees valid trace shapes");
    let leaf_to_air = trace_order.preprocessed_air_for_leaf::<F, EF, _>(airs);

    let leaves = preprocessed.committed.tree().leaves();
    if leaves.len() != leaf_to_air.len() {
        return Err(PreprocessedValidationError::TreeLengthMismatch {
            expected: leaf_to_air.len(),
            actual: leaves.len(),
        });
    }

    for (leaf, &air_idx_u8) in leaf_to_air.iter().enumerate() {
        let air_idx = air_idx_u8 as usize;
        let expected = airs[air_idx].preprocessed_width();
        let actual = leaves[leaf].width();
        if actual != expected {
            return Err(PreprocessedValidationError::WidthMismatch {
                leaf,
                air: air_idx,
                expected,
                actual,
            });
        }
        if let Some(preproc) = &preprocessed.traces[air_idx] {
            let main = main_traces[air_idx].height();
            if preproc.height() != main {
                return Err(PreprocessedValidationError::HeightMismatch {
                    air: air_idx,
                    main,
                    preprocessed: preproc.height(),
                });
            }
        }
    }

    // The PCS currently requires every top-level tree to share the max LDE
    // height, so the tallest preprocessed leaf must reach the max trace height.
    // Compare unlifted heights so the check is blowup-independent.
    let max_trace = 1usize << trace_order.max_log_height() as usize;
    let max_preproc = preprocessed
        .traces
        .iter()
        .filter_map(|t| t.as_ref().map(Matrix::height))
        .max()
        .unwrap_or(0);
    if max_preproc != max_trace {
        return Err(PreprocessedValidationError::MaxHeightBelowMaxTrace {
            preprocessed: max_preproc,
            max_trace,
        });
    }

    Ok(())
}

/// Errors from constructing a stark-layer statement: preprocessed presence
/// parity and (prover side) the bundle's shape against the AIR declarations.
#[derive(Debug, Error)]
pub enum PreprocessedValidationError {
    #[error("AIRs declare preprocessed columns but no preprocessed bundle was supplied")]
    TreeExpected,
    #[error("a preprocessed bundle was supplied but no AIR declares preprocessed columns")]
    TreeUnexpected,
    #[error("AIRs declare preprocessed columns but no preprocessed commitment was supplied")]
    CommitmentExpected,
    #[error("a preprocessed commitment was supplied but no AIR declares preprocessed columns")]
    CommitmentUnexpected,
    #[error(
        "preprocessed leaf {leaf} (AIR {air}) width mismatch: AIR declares {expected}, tree has {actual}"
    )]
    WidthMismatch {
        leaf: usize,
        air: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "preprocessed tree leaf count {actual} does not match the preprocessed-AIR count {expected}"
    )]
    TreeLengthMismatch { expected: usize, actual: usize },
    #[error(
        "AIR {air}: preprocessed matrix height ({preprocessed}) does not match main trace height ({main})"
    )]
    HeightMismatch {
        air: usize,
        main: usize,
        preprocessed: usize,
    },
    #[error(
        "preprocessed tree's tallest leaf ({preprocessed}) is below the max trace height \
         ({max_trace}); PCS requires matching LDE heights across trees"
    )]
    MaxHeightBelowMaxTrace { preprocessed: usize, max_trace: usize },
}

// ============================================================================
// StarkProverStatement
// ============================================================================

/// Prover-side bundle: a [`StarkConfig`], an owned [`ProverStatement`], and the
/// optional borrowed [`Preprocessed`] data.
pub struct StarkProverStatement<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    config: &'a SC,
    prover_statement: &'a ProverStatement<F, EF, MA>,
    preprocessed: Option<&'a Preprocessed<F, SC::Lmcs>>,
}

impl<'a, F, EF, MA, SC> StarkProverStatement<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    /// Bundle a config + prover statement with no preprocessed data.
    ///
    /// Errors with [`PreprocessedValidationError::TreeExpected`] if any AIR
    /// declares preprocessed columns — use [`Self::with_preprocessed`] instead.
    pub fn new(
        config: &'a SC,
        prover_statement: &'a ProverStatement<F, EF, MA>,
    ) -> Result<Self, PreprocessedValidationError> {
        if prover_statement.statement().airs().iter().any(|a| a.preprocessed_width() > 0) {
            return Err(PreprocessedValidationError::TreeExpected);
        }
        Ok(Self {
            config,
            prover_statement,
            preprocessed: None,
        })
    }

    /// Bundle a config + prover statement with a prebuilt preprocessed bundle,
    /// validating it against the AIRs.
    pub fn with_preprocessed(
        config: &'a SC,
        prover_statement: &'a ProverStatement<F, EF, MA>,
        preprocessed: &'a Preprocessed<F, SC::Lmcs>,
    ) -> Result<Self, PreprocessedValidationError> {
        validate_preprocessed(prover_statement, preprocessed)?;
        Ok(Self {
            config,
            prover_statement,
            preprocessed: Some(preprocessed),
        })
    }

    /// Borrow the STARK configuration.
    pub fn config(&self) -> &SC {
        self.config
    }

    /// Borrow the wrapped air-crate prover statement.
    pub fn prover_statement(&self) -> &ProverStatement<F, EF, MA> {
        self.prover_statement
    }

    /// Borrow the verifier-side statement (the AIRs + public inputs).
    pub fn statement(&self) -> &Statement<F, EF, MA> {
        self.prover_statement.statement()
    }

    /// Commitment to the preprocessed tree, for the verifier's
    /// [`StarkStatement::with_preprocessed`]; `None` when there is none.
    pub fn preprocessed_commitment(&self) -> Option<<SC::Lmcs as Lmcs>::Commitment> {
        self.preprocessed.map(|p| p.commitment())
    }

    /// Borrow the preprocessed bundle, if any.
    pub(crate) fn preprocessed(&self) -> Option<&Preprocessed<F, SC::Lmcs>> {
        self.preprocessed
    }
}

// ============================================================================
// StarkStatement
// ============================================================================

/// Verifier-side bundle: a [`StarkConfig`], a borrowed [`Statement`], and the
/// optional preprocessed commitment (a trusted setup input, not read from the
/// proof).
pub struct StarkStatement<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    config: &'a SC,
    statement: &'a Statement<F, EF, MA>,
    preprocessed_commitment: Option<<SC::Lmcs as Lmcs>::Commitment>,
}

impl<'a, F, EF, MA, SC> StarkStatement<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    /// Bundle a config + statement with no preprocessed commitment.
    ///
    /// Errors with [`PreprocessedValidationError::CommitmentExpected`] if any
    /// AIR declares preprocessed columns — use [`Self::with_preprocessed`].
    pub fn new(
        config: &'a SC,
        statement: &'a Statement<F, EF, MA>,
    ) -> Result<Self, PreprocessedValidationError> {
        if statement.airs().iter().any(|a| a.preprocessed_width() > 0) {
            return Err(PreprocessedValidationError::CommitmentExpected);
        }
        Ok(Self {
            config,
            statement,
            preprocessed_commitment: None,
        })
    }

    /// Bundle a config + statement with the preprocessed commitment.
    pub fn with_preprocessed(
        config: &'a SC,
        statement: &'a Statement<F, EF, MA>,
        commitment: <SC::Lmcs as Lmcs>::Commitment,
    ) -> Result<Self, PreprocessedValidationError> {
        if !statement.airs().iter().any(|a| a.preprocessed_width() > 0) {
            return Err(PreprocessedValidationError::CommitmentUnexpected);
        }
        Ok(Self {
            config,
            statement,
            preprocessed_commitment: Some(commitment),
        })
    }

    /// Borrow the STARK configuration.
    pub fn config(&self) -> &SC {
        self.config
    }

    /// Borrow the wrapped air-crate statement.
    pub fn statement(&self) -> &Statement<F, EF, MA> {
        self.statement
    }

    /// Borrow the preprocessed commitment, if any.
    pub(crate) fn preprocessed_commitment(&self) -> Option<&<SC::Lmcs as Lmcs>::Commitment> {
        self.preprocessed_commitment.as_ref()
    }
}
