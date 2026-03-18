//! Local copy of `BitReversibleMatrix` with additional impls for [`FlatMatrixView`].
//!
//! # Temporary stopgap
//!
//! The upstream `BitReversibleMatrix` trait in `p3-matrix` is only implemented for
//! [`DenseMatrix`], not for [`FlatMatrixView`]. This module provides an identical
//! trait with impls for all matrix types used by the LMCS and FRI.
//!
//! Once an upstream impl is available, this module can be removed and all uses
//! replaced with `p3_matrix::bitrev::BitReversibleMatrix`.

use p3_field::{ExtensionField, Field};
use p3_matrix::{
    Matrix,
    bitrev::{BitReversalPerm, BitReversedMatrixView},
    dense::{DenseMatrix, DenseStorage},
    extension::FlatMatrixView,
};

/// A matrix that supports bit-reversed row reordering.
///
/// Local copy of `p3_matrix::bitrev::BitReversibleMatrix` extended with impls for
/// [`FlatMatrixView`]. See [module docs](self) for migration notes.
pub trait BitReversibleMatrix<T: Send + Sync + Clone>: Matrix<T> {
    /// The type returned when this matrix is viewed in bit-reversed order.
    type BitRev: BitReversibleMatrix<T>;

    /// Return a version of the matrix with its row order reversed by bit index.
    fn bit_reverse_rows(self) -> Self::BitRev;
}

// ============================================================================
// DenseMatrix impls (mirrors upstream)
// ============================================================================

impl<T, S> BitReversibleMatrix<T> for DenseMatrix<T, S>
where
    T: Clone + Send + Sync,
    S: DenseStorage<T>,
{
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

impl<T, S> BitReversibleMatrix<T> for BitReversedMatrixView<DenseMatrix<T, S>>
where
    T: Clone + Send + Sync,
    S: DenseStorage<T>,
{
    type BitRev = DenseMatrix<T, S>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        self.inner
    }
}

// ============================================================================
// FlatMatrixView impls (not available upstream)
// ============================================================================

impl<F, EF, Inner> BitReversibleMatrix<F> for FlatMatrixView<F, EF, Inner>
where
    F: Field,
    EF: ExtensionField<F>,
    Inner: Matrix<EF>,
{
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

impl<F, EF, Inner> BitReversibleMatrix<F> for BitReversedMatrixView<FlatMatrixView<F, EF, Inner>>
where
    F: Field,
    EF: ExtensionField<F>,
    Inner: Matrix<EF>,
{
    type BitRev = FlatMatrixView<F, EF, Inner>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        self.inner
    }
}
