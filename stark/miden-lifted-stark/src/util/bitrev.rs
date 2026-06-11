//! Bit-reversal materialization helper for LMCS / FRI commitments.

use p3_matrix::{
    Matrix,
    bitrev::{BitReversalPerm, BitReversedMatrixView, BitReversibleMatrix},
    dense::RowMajorMatrix,
};

/// Materialize a matrix into a domain-ordered [`BitReversedMatrixView`] over an owned
/// [`RowMajorMatrix`].
///
/// The returned view presents its rows in domain order and yields the owned bit-reversed
/// matrix when passed to [`Lmcs::build_tree`](crate::lmcs::Lmcs::build_tree) /
/// [`Lmcs::build_aligned_tree`](crate::lmcs::Lmcs::build_aligned_tree), which store it
/// without re-materializing.
pub(crate) fn materialize_bitrev<T: Clone + Send + Sync>(
    evals: impl BitReversibleMatrix<T>,
) -> BitReversedMatrixView<RowMajorMatrix<T>> {
    BitReversalPerm::new_view(evals.bit_reverse_rows().to_row_major_matrix())
}
