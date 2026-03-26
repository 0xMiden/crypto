//! Testing utilities for LMCS.
//!
//! Re-exports field/hash configurations from [`p3_miden_dev_utils`] and adds
//! `Lmcs` type aliases plus `test_lmcs()` constructors for each config.

use alloc::{vec, vec::Vec};

use p3_field::{Field, PackedValue, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::utils::aligned_len;

/// Goldilocks + Poseidon2 LMCS configuration and test fixtures.
pub mod goldilocks_poseidon2 {
    use alloc::vec::Vec;

    use p3_challenger::CanObserve;
    use p3_matrix::dense::RowMajorMatrix;
    pub use p3_miden_dev_utils::configs::goldilocks_poseidon2::*;
    use p3_miden_transcript::{ProverTranscript, TranscriptData, VerifierTranscript};
    use rand::{Rng, RngExt};

    use crate::Lmcs as LmcsTrait;

    /// LMCS configured with Goldilocks + Poseidon2.
    pub type Lmcs = crate::LmcsConfig<P, P, Sponge, Compress, WIDTH, DIGEST>;

    pub type TestTree = <Lmcs as LmcsTrait>::Tree<RowMajorMatrix<F>>;
    pub type TestCommitment = <Lmcs as LmcsTrait>::Commitment;
    pub type TestTranscriptData = TranscriptData<F, TestCommitment>;
    pub type TestDigest = <Challenger as p3_challenger::CanFinalizeDigest>::Digest;
    pub type TestProverChannel = ProverTranscript<F, TestCommitment, Challenger>;
    pub type TestVerifierChannel<'a> = VerifierTranscript<'a, F, TestCommitment, Challenger>;

    /// Create a test LMCS instance.
    pub fn test_lmcs() -> Lmcs {
        let (_, sponge, compress) = test_components();
        crate::LmcsConfig::new(sponge, compress)
    }

    pub fn prover_channel() -> TestProverChannel {
        ProverTranscript::new(test_challenger())
    }

    pub fn prover_channel_with_commitment(commitment: &TestCommitment) -> TestProverChannel {
        let mut challenger = test_challenger();
        challenger.observe(*commitment);
        ProverTranscript::new(challenger)
    }

    pub fn verifier_channel(data: &TestTranscriptData) -> TestVerifierChannel<'_> {
        VerifierTranscript::from_data(test_challenger(), data)
    }

    pub fn verifier_channel_with_commitment<'a>(
        data: &'a TestTranscriptData,
        commitment: &TestCommitment,
    ) -> TestVerifierChannel<'a> {
        let mut challenger = test_challenger();
        challenger.observe(*commitment);
        VerifierTranscript::from_data(challenger, data)
    }

    pub fn sample_indices<R: Rng>(rng: &mut R, upper: usize, count: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(count);
        for _ in 0..count {
            indices.push(rng.random_range(0..upper));
        }
        indices
    }
}

/// Goldilocks + Keccak LMCS configuration and test fixtures.
pub mod goldilocks_keccak {
    use alloc::vec::Vec;

    use p3_challenger::CanObserve;
    use p3_keccak::VECTOR_LEN;
    use p3_matrix::dense::RowMajorMatrix;
    pub use p3_miden_dev_utils::configs::goldilocks_keccak::*;
    use p3_miden_transcript::{ProverTranscript, TranscriptData, VerifierTranscript};
    use rand::{Rng, RngExt};

    use crate::Lmcs as LmcsTrait;

    /// LMCS configured with Goldilocks + Keccak (SIMD-parallel).
    pub type Lmcs =
        crate::LmcsConfig<[F; VECTOR_LEN], [u64; VECTOR_LEN], Sponge, Compress, WIDTH, DIGEST>;

    pub type TestTree = <Lmcs as LmcsTrait>::Tree<RowMajorMatrix<F>>;
    pub type TestCommitment = <Lmcs as LmcsTrait>::Commitment;
    pub type TestTranscriptData = TranscriptData<F, TestCommitment>;
    pub type TestDigest = <Challenger as p3_challenger::CanFinalizeDigest>::Digest;
    pub type TestProverChannel = ProverTranscript<F, TestCommitment, Challenger>;
    pub type TestVerifierChannel<'a> = VerifierTranscript<'a, F, TestCommitment, Challenger>;

    /// Create a test LMCS instance.
    pub fn test_lmcs() -> Lmcs {
        let (sponge, compress) = test_components();
        crate::LmcsConfig::new(sponge, compress)
    }

    pub fn prover_channel() -> TestProverChannel {
        ProverTranscript::new(test_challenger())
    }

    pub fn prover_channel_with_commitment(commitment: &TestCommitment) -> TestProverChannel {
        let mut challenger = test_challenger();
        challenger.observe(*commitment);
        ProverTranscript::new(challenger)
    }

    pub fn verifier_channel(data: &TestTranscriptData) -> TestVerifierChannel<'_> {
        VerifierTranscript::from_data(test_challenger(), data)
    }

    pub fn verifier_channel_with_commitment<'a>(
        data: &'a TestTranscriptData,
        commitment: &TestCommitment,
    ) -> TestVerifierChannel<'a> {
        let mut challenger = test_challenger();
        challenger.observe(*commitment);
        VerifierTranscript::from_data(challenger, data)
    }

    pub fn sample_indices<R: Rng>(rng: &mut R, upper: usize, count: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(count);
        for _ in 0..count {
            indices.push(rng.random_range(0..upper));
        }
        indices
    }
}

/// Common matrix group scenarios for testing lifting with varying heights.
///
/// Each scenario is a list of (height, width) pairs, sorted by ascending height.
/// The `rate` parameter controls the RATE-based width scenarios.
///
/// # Parameters
/// - `pack_width`: The SIMD packing width (e.g., `P::WIDTH` for packed field)
/// - `rate`: The sponge rate for width alignment scenarios
pub fn matrix_scenarios<P: PackedValue>(rate: usize) -> Vec<Vec<(usize, usize)>> {
    let pack_width = P::WIDTH.max(2);
    vec![
        // Single matrices
        vec![(1, 1)],
        vec![(1, rate - 1)],
        // Multiple heights (must be ascending)
        vec![(2, 3), (4, 5), (8, rate)],
        vec![(1, 5), (1, 3), (2, 7), (4, 1), (8, rate + 1)],
        // Packing boundary tests
        vec![
            (pack_width / 2, rate - 1),
            (pack_width, rate),
            (pack_width * 2, rate + 3),
        ],
        vec![(pack_width, rate + 5), (pack_width * 2, 25)],
        vec![
            (1, rate * 2),
            (pack_width / 2, rate * 2 - 1),
            (pack_width, rate * 2),
            (pack_width * 2, rate * 3 - 2),
        ],
        // Same-height matrices
        vec![(4, rate - 1), (4, rate), (8, rate + 3), (8, rate * 2)],
        // Single tall matrix
        vec![(pack_width * 2, rate - 1)],
    ]
}

/// Concatenate matrices horizontally, padding each to a multiple of `R`.
///
/// All matrices are lifted to the maximum height first.
pub fn concatenate_matrices<F: Field + PrimeCharacteristicRing, const R: usize>(
    matrices: &[RowMajorMatrix<F>],
) -> RowMajorMatrix<F> {
    let max_height = matrices.last().unwrap().height();
    let width: usize = matrices.iter().map(|m| aligned_len(m.width(), R)).sum();

    let concatenated_data: Vec<_> = (0..max_height)
        .flat_map(|idx| {
            matrices.iter().flat_map(move |m| {
                let mut row = m.row_slice(idx).unwrap().to_vec();
                let padded_width = aligned_len(row.len(), R);
                row.resize(padded_width, F::ZERO);
                row
            })
        })
        .collect();
    RowMajorMatrix::new(concatenated_data, width)
}
