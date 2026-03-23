//! Lifted Matrix Commitment Scheme (LMCS) for matrices with power-of-two heights.
//!
//! This crate provides a Merkle tree commitment scheme for matrices that store
//! polynomial evaluations over multiplicative cosets. The tree is indexed by
//! **domain order** (natural index): callers address leaves by domain index,
//! and bit-reversal concerns are encapsulated inside the LMCS.
//!
//! # Main Types
//!
//! - [`LmcsConfig`]: Configuration holding cryptographic primitives (sponge + compression)
//!   with packed types for SIMD parallelization.
//! - [`Lmcs`]: Trait for LMCS configurations, providing type-erased access to commitment operations.
//! - [`LmcsTree`]: Trait for built LMCS trees, providing opening operations.
//! - [`LiftedMerkleTree`]: The underlying Merkle tree data structure.
//! - [`Proof`]: Single-opening proof with rows, optional salt, and authentication path.
//! - [`BatchProof`]: Batch opening data with Merkle witness for path extraction.
//!
//! # API Overview
//!
//! ## Direct Usage (Simple)
//!
//! ```ignore
//! use p3_miden_lmcs::{HidingLmcsConfig, Lmcs, LmcsConfig, LmcsTree};
//! use p3_miden_transcript::{ProverTranscript, VerifierTranscript};
//!
//! // Config captures PF, PD (packed types), H, C, WIDTH, DIGEST
//! // F = PF::Value and D = PD::Value are derived
//! let config = LmcsConfig::<PF, PD, _, _, WIDTH, DIGEST>::new(sponge, compress);
//! let challenger = /* ... */;
//!
//! // Build tree - no turbofish needed, packed types are known from config
//! let tree = config.build_aligned_tree(matrices);
//! let root = tree.root();
//! let mut prover_channel = ProverTranscript::new(challenger);
//! tree.prove_batch(&indices, &mut prover_channel);
//! let (_, transcript) = prover_channel.finalize();
//!
//! let mut verifier_channel = VerifierTranscript::from_data(challenger, &transcript);
//! let rows = config.open_batch(&root, &widths, log_max_height, &indices, &mut verifier_channel)?;
//!
//! // For hiding commitment with salt, use HidingLmcsConfig with RNG
//! let hiding_config =
//!     HidingLmcsConfig::<PF, PD, _, _, _, WIDTH, DIGEST, 4>::new(sponge, compress, rng);
//! let tree = hiding_config.build_aligned_tree(matrices);
//! ```
//!
//! ## Trait-Based Usage (for generic code like FRI)
//!
//! ```ignore
//! use p3_miden_lmcs::{Lmcs, LmcsTree};
//! use p3_miden_transcript::ProverTranscript;
//!
//! fn commit_and_open<L: Lmcs>(lmcs: &L, matrices: Vec<impl Matrix<L::F>>) {
//!     let tree = lmcs.build_aligned_tree(matrices);
//!     let commitment = tree.root();
//!     let challenger = /* ... */;
//!     let mut channel = ProverTranscript::new(challenger);
//!     tree.prove_batch(&[0, 1, 2], &mut channel);
//!     // ...
//! }
//! ```
//!
//! ## Transcript Hints
//!
//! For the `LmcsConfig`/`LiftedMerkleTree` implementation in this crate, batch openings
//! are streamed as transcript hints: for each unique query index **in sorted tree index order**
//! (ascending, deduplicated), `prove_batch` writes one row per matrix (in tree
//! leaf order) followed by optional salt. After all indices, missing sibling hashes are
//! emitted level-by-level in canonical left-to-right, bottom-to-top order. Hints are not
//! observed into the Fiat-Shamir challenger.
//!
//! `LmcsConfig::open_batch` consumes only the hints it needs to reconstruct the root;
//! extra hint data is left unread. It expects `widths` and `log_max_height` to match the
//! committed tree and treats empty `indices` as invalid. Use
//! [`Lmcs::read_batch_proof`] to parse hints into a [`BatchProof`]
//! without verifying against a commitment.
//!
//! # Mathematical Foundation
//!
//! Consider a polynomial `f(X)` of degree less than `d`, and let `g` be the coset generator and
//! `K` a subgroup of order `n ≥ d` with primitive root `ω`. The coset evaluations
//! `{f(g·ω^j) : j ∈ [0, n)}` can be stored in two orderings:
//!
//! - **Canonical order**: `[f(g·ω^0), f(g·ω^1), ..., f(g·ω^{n-1})]`
//! - **Bit-reversed order**: `[f(g·ω^{bitrev(0)}), f(g·ω^{bitrev(1)}), ..., f(g·ω^{bitrev(n-1)})]`
//!
//! where `bitrev(i)` is the bit-reversal of index `i` within `log2(n)` bits.
//!
//! # Lifting by Upsampling
//!
//! When we have matrices with different heights n₀ ≤ n₁ ≤ … ≤ nₜ₋₁ (each a power of two),
//! we "lift" smaller matrices to the maximum height N = nₜ₋₁ using **nearest-neighbor
//! upsampling**: each row is repeated contiguously `r = N/n` times.
//!
//! For a matrix of height `n` lifted to `N`, the index map is: `i ↦ floor(i / r) = i >> log2(r)`
//!
//! **Example** (`n=4`, `N=8`):
//! - Original rows: `[row0, row1, row2, row3]`
//! - Upsampled: `[row0, row0, row1, row1, row2, row2, row3, row3]` (blocks of 2)
//!
//! # Why Upsampling Works
//!
//! Given evaluations of `f(X)` over a coset, upsampling to height `N = n · r` (where `r = 2^k`)
//! produces evaluations of the lifted polynomial `f'(X) = f(Xʳ)` over the larger coset.
//!
//! The internal hashing uses matrices whose rows are in bit-reversed order (as produced by
//! `BitReversedMatrixView`). For such data, upsampling by nearest-neighbor repetition
//! (`i >> k`) produces the correct lifted evaluations. The LMCS then bit-reverses the
//! leaf digest array so the Merkle tree is indexed by domain order.
//!
//! # Opening Semantics
//!
//! When opening at domain index `d`, the LMCS maps `d` to bit-reversed row index
//! `bitrev(d) >> k` for each matrix. This returns the same values that were hashed
//! into Merkle leaf `d`.
//!
//! # Equivalence to Cyclic Lifting
//!
//! Upsampling bit-reversed data is equivalent to cyclically repeating canonically-ordered data:
//!
//! ```text
//! Upsample(BitReverse(data)) = BitReverse(Cyclic(data))
//! ```
//!
//! where cyclic repetition tiles the original `n` rows periodically: `[row0, row1, ..., row_{n-1}, row0, ...]`.
//!
//! This equivalence follows from the bit-reversal identity: for `r = N/n = 2^k`,
//! `bitrev_N(i) mod n = bitrev_n(i >> k)`.

#![no_std]

extern crate alloc;

pub mod bitrev;
mod hiding_lmcs;
mod lifted_tree;
mod lmcs;
pub mod merkle_witness;
mod node_id;
pub mod proof;
pub mod row_list;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;
mod tree_indices;
pub mod utils;

use alloc::{collections::BTreeMap, vec::Vec};

// ============================================================================
// Public Re-exports
// ============================================================================
pub use bitrev::{BitReversibleMatrix, materialize_bitrev};
pub use hiding_lmcs::HidingLmcsConfig;
pub use lifted_tree::LiftedMerkleTree;
pub use lmcs::LmcsConfig;
pub use merkle_witness::MerkleWitness;
pub use node_id::NodeId;
use p3_matrix::Matrix;
use p3_miden_transcript::{ProverChannel, TranscriptError, VerifierChannel};
pub use proof::{BatchProof, BatchProofView, LeafOpening, Proof};
pub use row_list::RowList;
use thiserror::Error;
pub use tree_indices::{MissingSiblingsIter, TreeIndices};
pub use utils::log2_strict_u8;

// ============================================================================
// Type Aliases
// ============================================================================

/// Opened rows keyed by leaf index, returned by [`Lmcs::open_batch`].
pub type OpenedRows<F> = BTreeMap<usize, RowList<F>>;

// ============================================================================
// Traits
// ============================================================================

/// Trait for LMCS configurations.
pub trait Lmcs: Clone {
    /// Scalar field element type for matrix data.
    ///
    /// `Send + Sync` bounds required by [`Matrix<F>`].
    type F: Clone + Send + Sync;
    /// Commitment type (root hash).
    type Commitment: Clone + Eq;
    /// Tree type (prover data), parameterized by stored matrix type.
    type Tree<Stored: Matrix<Self::F>>: LmcsTree<Self::F, Self::Commitment, Stored>;
    /// Batch witness type returned by [`read_batch_proof`](Self::read_batch_proof).
    type BatchProof: BatchProofView<Self::F, Self::Commitment>;

    /// Build a tree from domain-ordered matrices with no transcript padding (alignment = 1).
    ///
    /// The LMCS extracts the inner bit-reversed matrices via
    /// [`BitReversibleMatrix::bit_reverse_rows`] and stores them. The tree is indexed
    /// by domain order; [`LmcsTree::leaves`] returns the stored bit-reversed matrices.
    ///
    /// This affects only transcript hint formatting; the commitment root is unchanged.
    fn build_tree<M: BitReversibleMatrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M::BitRev>;

    /// Build a tree from domain-ordered matrices using the hasher alignment for transcript
    /// padding.
    ///
    /// Rows are padded to the hasher's alignment when streaming hints.
    /// When the alignment is 1, this is identical to [`Self::build_tree`].
    fn build_aligned_tree<M: BitReversibleMatrix<Self::F>>(
        &self,
        leaves: Vec<M>,
    ) -> Self::Tree<M::BitRev>;

    /// Hash a sequence of field slices into a leaf hash.
    ///
    /// Inputs are absorbed in order. For salted leaves, append the salt slice to the
    /// iterator (or call this with a chained iterator).
    fn hash<'a, I>(&self, rows: I) -> Self::Commitment
    where
        I: IntoIterator<Item = &'a [Self::F]>,
        Self::F: 'a;

    /// Compress two hashes into their parent (2-to-1 compression).
    fn compress(&self, left: Self::Commitment, right: Self::Commitment) -> Self::Commitment;

    /// Open a batch proof by reading hint data from a transcript channel.
    ///
    /// The hint format is implementation-defined; callers must use the matching
    /// `LmcsTree::prove_batch` implementation to produce compatible hints.
    /// `widths` must match the committed tree (including any alignment padding
    /// if `build_aligned_tree` was used).
    ///
    /// # Preconditions
    /// - `indices` must be non-empty and have depth matching `log₂(tree height)`.
    ///
    /// # Postconditions
    /// On success, the returned map contains exactly one entry per unique index.
    /// Each entry's `RowList<F>` has one row per width in `widths`, with that
    /// row's length matching the corresponding width.
    fn open_batch<Ch>(
        &self,
        commitment: &Self::Commitment,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<OpenedRows<Self::F>, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>;

    /// Parse a batch opening from transcript hints without verification.
    ///
    /// Reads leaf openings and sibling hashes from the channel, hashes leaves,
    /// and reconstructs the Merkle witness. Does not verify against a commitment;
    /// validation happens in [`open_batch`](Lmcs::open_batch).
    ///
    /// Use [`MerkleWitness::path`] on the returned witness to extract authentication paths.
    fn read_batch_proof<Ch>(
        &self,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>;

    /// Get the alignment used by `build_aligned_tree`.
    ///
    /// This is the hasher's rate, used to pad rows when streaming hints.
    fn alignment(&self) -> usize;
}

/// Trait for built LMCS trees.
///
/// Provides methods for accessing tree data and generating proofs.
pub trait LmcsTree<F, Commitment, M> {
    /// Get the tree root (commitment).
    fn root(&self) -> Commitment;

    /// Get the height of the largest matrix (i.e. the number of leaves of the Merkle tree).
    fn height(&self) -> usize;

    /// Get references to the committed matrices.
    ///
    /// Matrix widths are not padded; use [`Self::aligned_widths`] for aligned widths.
    fn leaves(&self) -> &[M];

    /// Get the opened rows for a given leaf index (original matrix widths, no padding).
    fn rows(&self, index: usize) -> RowList<F>;

    /// Get the opened rows for a given leaf index, padded to the tree's alignment.
    ///
    /// Padding uses `Default::default()` and is not enforced by verification.
    fn aligned_rows(&self, index: usize) -> RowList<F>;

    /// Column alignment used when streaming openings.
    fn alignment(&self) -> usize;

    /// Get widths for each committed matrix (original, no padding).
    fn widths(&self) -> Vec<usize>;

    /// Get aligned widths for each committed matrix (padded to alignment).
    fn aligned_widths(&self) -> Vec<usize> {
        let alignment = self.alignment();
        self.widths()
            .into_iter()
            .map(|w| utils::aligned_len(w, alignment))
            .collect()
    }

    /// Prove a batch opening and stream it into a transcript channel.
    ///
    /// The hint format is implementation-defined and must be consumed by the
    /// corresponding `Lmcs::open_batch` implementation. Rows are padded to the
    /// tree's alignment before being written to the channel.
    ///
    /// Leaf openings are written in **sorted tree index order** (ascending, deduplicated).
    fn prove_batch<Ch>(&self, indices: &TreeIndices, channel: &mut Ch)
    where
        Ch: ProverChannel<F = F, Commitment = Commitment>;
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during LMCS operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LmcsError {
    #[error("invalid proof")]
    InvalidProof,
    #[error("root mismatch")]
    RootMismatch,
    #[error("transcript error: {0}")]
    TranscriptError(#[from] TranscriptError),
}
