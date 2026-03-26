//! Testing utilities for the lifted FRI PCS.
//!
//! Re-exports LMCS testing configs and adds LDE matrix generation.

use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, TwoAdicField};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
pub use p3_miden_lmcs::testing::*;
use rand::{
    distr::{Distribution, StandardUniform},
    rngs::SmallRng,
};

/// Generate a matrix of LDE evaluations for random low-degree polynomials.
///
/// Each column is a polynomial of degree `poly_degree`, evaluated on the coset gK
/// in bit-reversed order, where g = `shift` and K is a subgroup of order `lde_size`.
///
/// The coset evaluation is computed by scaling coefficients: for f(X) = sum c_j X^j,
/// the coset evaluations f(gX) = sum (c_j g^j) X^j are obtained by DFT of scaled coefficients.
pub fn random_lde_matrix<F, V>(
    rng: &mut SmallRng,
    log_poly_degree: u8,
    log_blowup: u8,
    num_columns: usize,
    shift: F,
) -> RowMajorMatrix<V>
where
    F: TwoAdicField,
    V: BasedVectorSpace<F> + Clone + Send + Sync + Default,
    StandardUniform: Distribution<V>,
{
    let poly_degree = 1 << log_poly_degree as usize;
    let dft = Radix2DFTSmallBatch::<F>::default();

    let evals = RowMajorMatrix::rand(rng, poly_degree, num_columns);
    let lde = dft.coset_lde_algebra_batch(evals, log_blowup as usize, shift);
    lde.bit_reverse_rows().to_row_major_matrix()
}
