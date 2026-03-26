//! LMCS configuration types.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::marker::PhantomData;

use p3_field::PackedValue;
use p3_matrix::Matrix;
use p3_miden_stateful_hasher::{Alignable, StatefulHasher};
use p3_miden_transcript::VerifierChannel;
use p3_symmetric::{Hash, PseudoCompressionFunction};

use crate::{BatchProof, LiftedMerkleTree, Lmcs, LmcsError, OpenedRows, utils::RowList};

type Opening<F, C> = (RowList<F>, C);

/// LMCS configuration holding cryptographic primitives (sponge + compression).
///
/// This implementation defines the transcript hint layout used by
/// [`LmcsTree::prove_batch`](crate::LmcsTree::prove_batch) and consumed by
/// `open_batch` and [`BatchProof::read_from_channel`](crate::BatchProof::read_from_channel):
/// - For each *distinct* query index (in caller order, skipping duplicates): one row per
///   matrix (in leaf order), then `SALT_ELEMS` field elements of salt.
/// - After all indices: missing sibling hashes, level-by-level, left-to-right, bottom-to-top.
///
/// Hints are not observed into the Fiat-Shamir challenger.
///
/// `open_batch` expects `widths` and `log_max_height` to match the committed tree,
/// rejects empty `indices`, and ignores extra hint data. Widths must match the
/// committed row lengths (including any alignment padding if `build_aligned_tree`
/// was used). Duplicate indices are coalesced in the returned openings.
/// [`BatchProof::read_from_channel`](crate::BatchProof::read_from_channel) parses
/// the same hint stream without hashing, and [`BatchProof::single_proofs`](crate::BatchProof::single_proofs)
/// can reconstruct per-index proofs (keyed by index) without verifying against a commitment. Empty indices
/// yield an empty `BatchProof`, and out-of-range indices return `InvalidProof`.
///
/// Padding note:
/// - LMCS does not enforce that aligned padding values are zero. Verifiers cannot
///   distinguish zero padding from arbitrary values unless they check those columns
///   in the opened rows or constrain them elsewhere.
///
/// For hiding commitments with salt, use [`crate::HidingLmcsConfig`] instead.
#[derive(Clone, Debug)]
pub struct LmcsConfig<
    PF,
    PD,
    H,
    C,
    const WIDTH: usize,
    const DIGEST: usize,
    const SALT_ELEMS: usize = 0,
> {
    /// Stateful sponge for hashing matrix rows into leaf hashes.
    pub sponge: H,
    /// 2-to-1 compression function for building internal tree nodes.
    pub compress: C,
    pub(crate) _phantom: PhantomData<(PF, PD)>,
}

impl<PF, PD, H, C, const WIDTH: usize, const DIGEST: usize, const SALT_ELEMS: usize>
    LmcsConfig<PF, PD, H, C, WIDTH, DIGEST, SALT_ELEMS>
{
    /// Create a new LMCS configuration.
    #[inline]
    pub const fn new(sponge: H, compress: C) -> Self {
        Self {
            sponge,
            compress,
            _phantom: PhantomData,
        }
    }
}

impl<PF, PD, H, C, const WIDTH: usize, const DIGEST: usize, const SALT_ELEMS: usize> Lmcs
    for LmcsConfig<PF, PD, H, C, WIDTH, DIGEST, SALT_ELEMS>
where
    PF: PackedValue + Default,
    PD: PackedValue + Default,
    H: StatefulHasher<PF::Value, [PD::Value; DIGEST], State = [PD::Value; WIDTH]>
        + StatefulHasher<PF, [PD; DIGEST], State = [PD; WIDTH]>
        + Alignable<PF::Value, PD::Value>
        + Sync,
    C: PseudoCompressionFunction<[PD::Value; DIGEST], 2>
        + PseudoCompressionFunction<[PD; DIGEST], 2>
        + Sync,
{
    type F = PF::Value;
    type Commitment = Hash<PF::Value, PD::Value, DIGEST>;
    type BatchProof = BatchProof<PF::Value, Self::Commitment, SALT_ELEMS>;
    type Tree<M: Matrix<PF::Value>> = LiftedMerkleTree<PF::Value, PD::Value, M, DIGEST, SALT_ELEMS>;

    /// Build a tree from matrices with no transcript padding (alignment = 1).
    ///
    /// Preconditions:
    /// - `leaves` is non-empty.
    /// - Matrix heights are powers of two and sorted by height (shortest to tallest).
    ///
    /// Panics if `leaves` is empty. Incorrect height order commits to a different
    /// lifted matrix than intended.
    fn build_tree<M: Matrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M> {
        const { assert!(SALT_ELEMS == 0) }
        LiftedMerkleTree::build_with_alignment::<PF, PD, H, C, WIDTH>(
            &self.sponge,
            &self.compress,
            leaves,
            None,
            1,
        )
    }

    /// Build a tree from matrices using the hasher alignment for transcript padding.
    ///
    /// Preconditions:
    /// - `leaves` is non-empty.
    /// - Matrix heights are powers of two and sorted by height (shortest to tallest).
    ///
    /// Panics if `leaves` is empty. Incorrect height order commits to a different
    /// lifted matrix than intended.
    fn build_aligned_tree<M: Matrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M> {
        const { assert!(SALT_ELEMS == 0) }
        LiftedMerkleTree::build_with_alignment::<PF, PD, H, C, WIDTH>(
            &self.sponge,
            &self.compress,
            leaves,
            None,
            <H as Alignable<PF::Value, PD::Value>>::ALIGNMENT,
        )
    }

    fn hash<'a, I>(&self, rows: I) -> Self::Commitment
    where
        I: IntoIterator<Item = &'a [Self::F]>,
        Self::F: 'a,
    {
        let mut state = [PD::Value::default(); WIDTH];
        for row in rows {
            self.sponge.absorb_into(&mut state, row.iter().cloned());
        }
        let digest: [PD::Value; DIGEST] = self.sponge.squeeze(&state);
        Hash::from(digest)
    }

    fn compress(&self, left: Self::Commitment, right: Self::Commitment) -> Self::Commitment {
        let left_digest = *left.as_ref();
        let right_digest = *right.as_ref();
        Hash::from(self.compress.compress([left_digest, right_digest]))
    }

    /// Verify a batch opening from transcript hints.
    ///
    /// Security notes:
    /// - `widths` and `log_max_height` must describe the committed tree; they are not checked.
    /// - `widths` must match the committed row lengths (including any alignment padding
    ///   if `build_aligned_tree` was used); LMCS does not enforce that padded values are
    ///   zero. Verifiers cannot distinguish zero padding from arbitrary values unless
    ///   they check the opened rows or constrain them elsewhere.
    /// - Empty `indices` returns `InvalidProof`.
    /// - Duplicate indices are coalesced in the returned map (unique keys only).
    /// - Out-of-range indices (>= 2^log_max_height) return `InvalidProof`.
    /// - Missing siblings or malformed hints return `InvalidProof`.
    /// - Extra hints are ignored and left unread.
    /// - Returns `RootMismatch` only after a well-formed proof yields a different root.
    ///
    /// Leaf openings are read in **sorted tree index order** (ascending, deduplicated).
    fn open_batch<Ch>(
        &self,
        commitment: &Self::Commitment,
        widths: &[usize],
        log_max_height: u8,
        indices: impl IntoIterator<Item = usize>,
        channel: &mut Ch,
    ) -> Result<OpenedRows<Self::F>, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        let max_height = 1 << log_max_height as usize;

        // Collect and deduplicate indices. BTreeSet iteration yields sorted order.
        let unique_indices: BTreeSet<usize> = indices.into_iter().collect();

        if unique_indices.is_empty() {
            return Err(LmcsError::InvalidProof);
        }

        // Map index -> (rows, leaf_hash), filled in sorted order.
        let mut openings_by_index: BTreeMap<usize, Opening<Self::F, Self::Commitment>> =
            BTreeMap::new();

        let total_width: usize = widths.iter().sum();

        // Read openings in sorted tree index order.
        for index in unique_indices {
            if index >= max_height {
                return Err(LmcsError::InvalidProof);
            }

            // Read full leaf as a flat slice; RowList recovers per-matrix structure from widths.
            let elems = channel.receive_hint_field_slice(total_width)?.to_vec();
            let rows = RowList::new(elems, widths);

            // Recompute leaf hash from opened data to verify against the Merkle commitment.
            let leaf_hash = if SALT_ELEMS > 0 {
                let salt: [PF::Value; SALT_ELEMS] = channel.receive_hint_field_array()?;
                self.hash(rows.iter_rows().chain([salt.as_slice()]))
            } else {
                self.hash(rows.iter_rows())
            };

            openings_by_index.insert(index, (rows, leaf_hash));
        }

        // Recompute root from known leaves and streamed siblings.
        //
        // For a node at position p:
        // - sibling: p ^ 1
        // - parent: p >> 1
        // - left child: p & 1 == 0
        //
        // We walk level-by-level. If a sibling is not already known at a level, it must be
        // provided by the proof. After log_max_height steps, we expect a single root at position 0.
        //
        // Security notes:
        // - Completeness: missing siblings return InvalidProof.
        // - Canonical order: siblings are consumed left-to-right, bottom-to-top.
        // - Extra siblings are ignored and remain unread.
        let computed_commitment = {
            // We alternate between two vectors: one holds the current level's nodes (children),
            // the other accumulates the next level's nodes (parents). After each level, we swap them.
            let mut children: Vec<(usize, Self::Commitment)> = openings_by_index
                .iter()
                .map(|(&index, (_, hash))| (index, *hash))
                .collect();
            let mut parents = Vec::new();

            // Process each level from leaves (level 0) up to root (level tree_depth).
            for _level in 0..log_max_height as usize {
                parents.reserve(children.len());
                let mut children_iter = children.iter().peekable();

                while let Some((child_position, child_hash)) = children_iter.next() {
                    // Get sibling hash: either from known nodes (if next in sorted list) or from proof.
                    // When both children are known, the proof omits that sibling since it's redundant.
                    let sibling_position = child_position ^ 1;
                    let sibling_hash =
                        match children_iter.next_if(|(pos, _)| *pos == sibling_position) {
                            Some((_, hash)) => *hash,
                            None => *channel.receive_hint_commitment()?,
                        };

                    // Determine left/right ordering: left child has even position (bit 0 = 0).
                    let child_is_left = child_position & 1 == 0;
                    let (left_hash, right_hash) = if child_is_left {
                        (*child_hash, sibling_hash)
                    } else {
                        (sibling_hash, *child_hash)
                    };

                    let parent_hash = self.compress(left_hash, right_hash);
                    let parent_position = child_position >> 1;
                    parents.push((parent_position, parent_hash));
                }

                core::mem::swap(&mut children, &mut parents);
                parents.clear();
            }

            // Invariant: after `tree_depth` iterations, all leaf positions converge to a single root at 0.
            // If any of the indices were out of bounds, the final index would not be 0.
            // If no indices were provided, children is empty.
            match children.as_slice() {
                [(0, root)] => *root,
                _ => return Err(LmcsError::InvalidProof),
            }
        };

        // Compare against commitment.
        if computed_commitment != *commitment {
            return Err(LmcsError::RootMismatch);
        }

        // Return deduplicated openings keyed by index.
        Ok(openings_by_index
            .into_iter()
            .map(|(idx, (rows, _hash))| (idx, rows))
            .collect())
    }

    /// Parse batch hints without hashing.
    ///
    /// Notes:
    /// - `widths` and `log_max_height` are trusted parameters.
    /// - `widths` must match the committed row lengths (including any alignment padding
    ///   if `build_aligned_tree` was used).
    /// - Empty or out-of-range indices are not rejected here; they produce an
    ///   invalid proof that will fail in [`open_batch`](Lmcs::open_batch).
    fn read_batch_proof_from_channel<Ch>(
        &self,
        widths: &[usize],
        log_max_height: u8,
        indices: &[usize],
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        Ok(BatchProof::read_from_channel(
            widths,
            log_max_height,
            indices,
            channel,
        )?)
    }

    fn alignment(&self) -> usize {
        <H as Alignable<PF::Value, PD::Value>>::ALIGNMENT
    }
}
// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_miden_transcript::{ProverTranscript, TranscriptData, VerifierTranscript};

    use crate::{
        Lmcs, LmcsConfig, LmcsError, LmcsTree, log2_strict_u8, testing::goldilocks_poseidon2 as gl,
    };

    type TestLmcs = gl::Lmcs;
    type F = gl::F;

    fn small_matrix(height: usize, width: usize, seed: u64) -> RowMajorMatrix<F> {
        let values = (0..height * width)
            .map(|i| F::from_u64(seed + i as u64))
            .collect();
        RowMajorMatrix::new(values, width)
    }

    #[test]
    fn open_batch_cases() {
        let lmcs: TestLmcs = gl::test_lmcs();
        let matrices = vec![small_matrix(4, 2, 0), small_matrix(4, 3, 100)];
        let tree = lmcs.build_tree(matrices);
        let widths = tree.widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        let make_transcript = |indices: &[usize]| {
            let mut prover_channel = gl::prover_channel();
            tree.prove_batch(indices.iter().copied(), &mut prover_channel);
            prover_channel.finalize()
        };

        let assert_open = |indices: &[usize]| {
            let (prover_digest, transcript) = make_transcript(indices);
            let mut verifier_channel = gl::verifier_channel(&transcript);
            let opened = lmcs
                .open_batch(
                    &commitment,
                    &widths,
                    log_max_height,
                    indices.iter().copied(),
                    &mut verifier_channel,
                )
                .unwrap();
            for &idx in indices {
                assert_eq!(opened[&idx], tree.rows(idx));
            }
            let verifier_digest = verifier_channel
                .finalize()
                .expect("transcript should finalize cleanly");
            assert_eq!(prover_digest, verifier_digest);
        };

        assert_open(&[0]);
        assert_open(&[0, 1]);
        assert_open(&[0, 2]);
        assert_open(&[0, 1, 2, 3]);
        assert_open(&[2, 2]);

        let tiny_tree = lmcs.build_tree(vec![small_matrix(1, 1, 7)]);
        let widths_tiny = tiny_tree.widths();
        let log_tiny = log2_strict_u8(tiny_tree.height());
        let mut prover_channel = gl::prover_channel();
        tiny_tree.prove_batch([0], &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let opened = lmcs
            .open_batch(
                &tiny_tree.root(),
                &widths_tiny,
                log_tiny,
                [0],
                &mut verifier_channel,
            )
            .unwrap();
        assert_eq!(opened[&0], tiny_tree.rows(0));
        let verifier_digest = verifier_channel
            .finalize()
            .expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);

        // oob index
        let (_, transcript) = gl::prover_channel().finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        assert_eq!(
            lmcs.open_batch(
                &commitment,
                &widths,
                log_max_height,
                [tree.height()],
                &mut verifier_channel,
            ),
            Err(LmcsError::InvalidProof)
        );

        // wrong tree
        let (_, transcript) = make_transcript(&[0]);
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let wrong_tree = lmcs.build_tree(vec![small_matrix(4, 2, 999)]);
        assert_eq!(
            lmcs.open_batch(
                &wrong_tree.root(),
                &widths,
                log_max_height,
                [0],
                &mut verifier_channel,
            ),
            Err(LmcsError::RootMismatch)
        );

        // missing item from transcript
        let indices = [0usize];
        let (_, transcript) = make_transcript(&indices);
        let (fields, mut commitments) = transcript.into_parts();
        commitments.pop();
        let truncated = TranscriptData::new(fields, commitments);
        let mut verifier_channel = gl::verifier_channel(&truncated);
        assert_eq!(
            lmcs.open_batch(
                &commitment,
                &widths,
                log_max_height,
                indices,
                &mut verifier_channel,
            ),
            Err(LmcsError::TranscriptError(
                p3_miden_transcript::TranscriptError::NoMoreCommitments
            ))
        );

        // empty indices
        let (_, transcript) = gl::prover_channel().finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        assert_eq!(
            lmcs.open_batch(
                &commitment,
                &widths,
                log_max_height,
                [],
                &mut verifier_channel,
            ),
            Err(LmcsError::InvalidProof)
        );
    }

    /// Reproduces the "root mismatch" bug when using Goldilocks + Blake3 (byte-based hash).
    ///
    /// The lifted STARK only tests with field-based Poseidon2, never with byte-based hashes.
    /// This test isolates the LMCS layer to confirm that ChainingHasher<Blake3> +
    /// CompressionFunctionFromHasher<Blake3> work correctly for commit-then-open.
    #[test]
    fn goldilocks_blake3_roundtrip() {
        use alloc::{vec, vec::Vec};

        use p3_blake3::Blake3;
        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_goldilocks::Goldilocks;
        use p3_miden_stateful_hasher::ChainingHasher;
        use p3_miden_transcript::{ProverTranscript, VerifierTranscript};
        use p3_symmetric::CompressionFunctionFromHasher;

        type F = Goldilocks;
        type Sponge = ChainingHasher<Blake3>;
        type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
        const WIDTH: usize = 32;
        const DIGEST: usize = 32;
        type Blake3Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
        type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, 32>>;

        fn challenger() -> Challenger {
            SerializingChallenger64::from_hasher(vec![], Blake3)
        }

        let sponge = ChainingHasher::new(Blake3);
        let compress = CompressionFunctionFromHasher::new(Blake3);
        let lmcs: Blake3Lmcs = LmcsConfig::new(sponge, compress);

        // Single 4x2 matrix of constant values.
        let values: Vec<F> = (0..4 * 2).map(|i| F::from_u64(i as u64)).collect();
        let matrix = RowMajorMatrix::new(values, 2);

        let tree = lmcs.build_tree(vec![matrix]);
        let widths = tree.widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        // Prove then verify a single index.
        let mut prover_channel = ProverTranscript::new(challenger());
        tree.prove_batch([0usize], &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();

        let mut verifier_channel = VerifierTranscript::from_data(challenger(), &transcript);
        let opened = lmcs
            .open_batch(
                &commitment,
                &widths,
                log_max_height,
                [0usize],
                &mut verifier_channel,
            )
            .expect("Goldilocks+Blake3 LMCS roundtrip should verify");

        assert_eq!(opened[&0], tree.rows(0));
        let verifier_digest = verifier_channel
            .finalize()
            .expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);
    }

    /// Same as [`goldilocks_blake3_roundtrip`] but with a 24-byte BLAKE3 digest (BLAKE3-192).
    #[test]
    fn goldilocks_blake3_192_roundtrip() {
        use alloc::{vec, vec::Vec};

        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_goldilocks::Goldilocks;
        use p3_miden_blake3::Blake3_192;
        use p3_miden_stateful_hasher::ChainingHasher;
        use p3_symmetric::CompressionFunctionFromHasher;

        type F = Goldilocks;
        type Sponge = ChainingHasher<Blake3_192>;
        type Compress = CompressionFunctionFromHasher<Blake3_192, 2, 24>;
        const WIDTH: usize = 24;
        const DIGEST: usize = 24;
        type Blake3Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
        type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3_192, DIGEST>>;

        fn challenger() -> Challenger {
            SerializingChallenger64::new(HashChallenger::new(Vec::new(), Blake3_192))
        }

        let sponge = ChainingHasher::new(Blake3_192);
        let compress = CompressionFunctionFromHasher::new(Blake3_192);
        let lmcs: Blake3Lmcs = LmcsConfig::new(sponge, compress);

        let values: Vec<F> = (0..4 * 2).map(|i| F::from_u64(i as u64)).collect();
        let matrix = RowMajorMatrix::new(values, 2);

        let tree = lmcs.build_tree(vec![matrix]);
        let widths = tree.widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        let mut prover_channel = ProverTranscript::new(challenger());
        tree.prove_batch([0usize], &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();

        let mut verifier_channel = VerifierTranscript::from_data(challenger(), &transcript);
        let opened = lmcs
            .open_batch(
                &commitment,
                &widths,
                log_max_height,
                [0usize],
                &mut verifier_channel,
            )
            .expect("Goldilocks+Blake3-192 LMCS roundtrip should verify");

        assert_eq!(opened[&0], tree.rows(0));
        let verifier_digest = verifier_channel
            .finalize()
            .expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);
    }
}
