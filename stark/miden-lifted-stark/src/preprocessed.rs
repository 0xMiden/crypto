//! Preprocessed data: the fixed per-AIR matrices and their committed LDE tree.
//!
//! Preprocessed columns are *fixed circuit data* (lookup tables, selectors)
//! declared by the AIR via [`BaseAir::preprocessed_trace`] and committed once
//! at setup. The prover holds the cached raw matrices plus their LDE tree (the
//! [`Preprocessed`] bundle, built once and borrowed across proofs); the
//! verifier holds only the commitment (a root hash, trusted like the AIR list
//! itself).
//!
//! [`Preprocessed::build`] caches the by-value [`BaseAir::preprocessed_trace`]
//! evals and builds the aligned LDE tree. [`validate_preprocessed`] checks a
//! bundle against a prover statement's AIRs; it runs at
//! [`ProverInstance::new`](crate::ProverInstance::new) construction time, so the
//! prover never re-checks the shape.

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

        // Leaf order: preprocessed AIRs sorted by `(height, air_idx)`. This must
        // match the leaf↔AIR mapping the prover/verifier reconstruct via
        // `TraceOrder::preprocessed_air_for_leaf` (preprocessed AIRs in proof
        // order, i.e. sorted by `(main_trace_height, air_idx)`). The two
        // coincide because `validate_preprocessed` rejects any bundle whose
        // preprocessed height differs from the main trace height — so sorting by
        // the preprocessed matrix height here yields the same order. `build`
        // sees only the AIR list (fixed circuit data), not the witness traces,
        // so it cannot call `TraceOrder` directly.
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
    /// verifier via [`VerifierInstance::new`](crate::VerifierInstance::new).
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
///
/// Called by [`ProverInstance::new`](crate::ProverInstance::new) only when both
/// the AIRs declare preprocessed columns and a bundle is supplied; presence
/// parity is checked separately by the constructor.
pub(crate) fn validate_preprocessed<F, EF, MA, L>(
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

/// Errors from constructing a stark-layer instance: preprocessed presence
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
