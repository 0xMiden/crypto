//! Integration tests for LMCS.

use alloc::{collections::BTreeMap, vec, vec::Vec};

// ============================================================================
// Test Helpers and Re-exports
// ============================================================================
pub use gl::{Compress, DIGEST, F, P, RATE, Sponge, WIDTH};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
pub use crate::testing::concatenate_matrices;
use p3_miden_stateful_hasher::{Alignable, StatefulHasher};
use rand::{RngExt, SeedableRng, rngs::SmallRng};

use crate::{
    BatchProof, HidingLmcsConfig, LiftedMerkleTree, Lmcs, LmcsConfig, LmcsError, LmcsTree, Proof,
    log2_strict_u8,
    testing::goldilocks_poseidon2 as gl,
    utils::{RowList, aligned_len},
};

/// Type alias for local LMCS config.
pub type BaseLmcs = LmcsConfig<P, P, Sponge, Compress, WIDTH, DIGEST>;
type Commitment = <BaseLmcs as Lmcs>::Commitment;
type TestDigest = gl::TestDigest;
type TestTranscriptData = gl::TestTranscriptData;
type OpenedRows = BTreeMap<usize, RowList<F>>;

/// Create a local LMCS config.
pub fn lmcs() -> BaseLmcs {
    gl::test_lmcs()
}

/// Build leaf hashes for a single matrix (used for equivalence testing).
pub fn build_leaves_single(matrix: &RowMajorMatrix<F>, sponge: &Sponge) -> Vec<[F; DIGEST]> {
    matrix
        .rows()
        .map(|row| {
            let mut state = [F::ZERO; WIDTH];
            sponge.absorb_into(&mut state, row);
            sponge.squeeze(&state)
        })
        .collect()
}

fn verify_open_batch<C>(
    lmcs: &C,
    commitment: &Commitment,
    widths: &[usize],
    log_max_height: u8,
    indices: &[usize],
    transcript: &TestTranscriptData,
    prover_digest: &TestDigest,
) -> Result<OpenedRows, LmcsError>
where
    C: Lmcs<F = F, Commitment = Commitment>,
{
    let mut verifier_channel = gl::verifier_channel(transcript);
    let result = lmcs.open_batch(
        commitment,
        widths,
        log_max_height,
        indices.iter().copied(),
        &mut verifier_channel,
    );
    if result.is_ok() {
        let verifier_digest = verifier_channel
            .finalize()
            .expect("transcript should finalize cleanly");
        assert_eq!(verifier_digest, *prover_digest);
    }
    result
}

pub fn roundtrip_open_batch<C, M>(
    lmcs: &C,
    tree: &C::Tree<M>,
    indices: &[usize],
) -> Result<(TestTranscriptData, OpenedRows), LmcsError>
where
    C: Lmcs<F = F, Commitment = Commitment>,
    M: Matrix<F>,
{
    let widths = tree.widths();
    let log_max_height = log2_strict_u8(tree.height());

    let (prover_digest, transcript) = {
        let mut prover_channel = gl::prover_channel();
        tree.prove_batch(indices.iter().copied(), &mut prover_channel);
        prover_channel.finalize()
    };
    let opened_rows = verify_open_batch(
        lmcs,
        &tree.root(),
        &widths,
        log_max_height,
        indices,
        &transcript,
        &prover_digest,
    )?;
    Ok((transcript, opened_rows))
}

// ============================================================================
// Hiding LMCS Types and Helpers
// ============================================================================

const SALT: usize = 4;
type HidingTree<M> = LiftedMerkleTree<F, F, M, DIGEST, SALT>;
type HidingConfig = HidingLmcsConfig<P, P, Sponge, Compress, SmallRng, WIDTH, DIGEST, SALT>;

fn hiding_lmcs(rng: SmallRng) -> HidingConfig {
    let (_, sponge, compress) = gl::test_components();
    HidingLmcsConfig::new(sponge, compress, rng)
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn lmcs_roundtrip() {
    let test = |seed: u64, matrices: &[(usize, usize)], num_queries: usize| {
        let mut rng = SmallRng::seed_from_u64(seed);
        let lmcs = lmcs();
        let matrices: Vec<_> = matrices
            .iter()
            .map(|&(h, w)| RowMajorMatrix::rand(&mut rng, h, w))
            .collect();

        let tree = lmcs.build_tree(matrices);
        let widths = tree.widths();
        let max_height = tree.height();
        let indices: Vec<usize> = (0..num_queries)
            .map(|_| rng.random_range(0..max_height))
            .collect();
        let (_transcript, opened_rows) =
            roundtrip_open_batch(&lmcs, &tree, &indices).expect("batch opening should verify");

        for (&leaf_idx, rows_for_query) in &opened_rows {
            assert_eq!(rows_for_query.num_rows(), widths.len());
            assert_eq!(*rows_for_query, tree.rows(leaf_idx));
        }
    };

    test(1, &[(8, 4)], 1); // single matrix
    test(42, &[(4, 3), (8, 5), (16, 7)], 4); // multi-height
    test(99, &[(32, 2)], 8); // tall matrix
}

#[test]
fn lmcs_duplicate_indices_roundtrip() {
    let mut rng = SmallRng::seed_from_u64(123);
    let lmcs = lmcs();
    let matrices = vec![
        RowMajorMatrix::rand(&mut rng, 4, 5),
        RowMajorMatrix::rand(&mut rng, 8, 3),
    ];

    let tree = lmcs.build_tree(matrices);
    let widths = tree.widths();
    let log_max_height = log2_strict_u8(tree.height());
    let indices = [3usize, 1, 3, 0, 1];

    let (transcript, opened_rows) =
        roundtrip_open_batch(&lmcs, &tree, &indices).expect("batch opening should verify");

    // BTreeMap coalesces duplicates: 5 indices → 3 unique keys
    assert_eq!(opened_rows.len(), 3);

    for (&index, rows) in &opened_rows {
        assert_eq!(*rows, tree.rows(index), "row mismatch for index {index}");
    }

    let mut verifier_channel = gl::verifier_channel(&transcript);
    let batch = BatchProof::<F, Commitment>::read_from_channel(
        &widths,
        log_max_height,
        &indices,
        &mut verifier_channel,
    )
    .expect("batch proof should parse from transcript");

    assert_eq!(batch.openings.len(), 3);
    for &index in &[0usize, 1, 3] {
        let opening = batch.openings.get(&index).expect("opening for index");
        assert_eq!(
            opening.rows,
            tree.rows(index),
            "batch opening rows mismatch for index {index}"
        );
    }

    let proofs = batch
        .single_proofs(&lmcs, &widths, log_max_height)
        .expect("batch proof should reconstruct proofs");
    assert_eq!(proofs.len(), 3);
}

#[test]
fn hiding_roundtrip() {
    let test = |seed: u64, matrices: &[(usize, usize)], indices: &[usize]| {
        let mut rng = SmallRng::seed_from_u64(seed);
        let matrices: Vec<_> = matrices
            .iter()
            .map(|&(h, w)| RowMajorMatrix::rand(&mut rng, h, w))
            .collect();

        let config = hiding_lmcs(rng);
        let tree: HidingTree<_> = config.build_tree(matrices);
        let (_transcript, opened_rows) =
            roundtrip_open_batch(&config, &tree, indices).expect("batch opening should verify");

        for (&leaf_idx, rows) in &opened_rows {
            assert_eq!(*rows, tree.rows(leaf_idx));
        }
    };

    test(99, &[(4, 3), (8, 5)], &[1, 3, 5]);

    // Different salts should produce different commitments
    let matrices1 = vec![RowMajorMatrix::rand(
        &mut SmallRng::seed_from_u64(100),
        4,
        3,
    )];
    let matrices2 = matrices1.clone();

    let config1 = hiding_lmcs(SmallRng::seed_from_u64(1));
    let config2 = hiding_lmcs(SmallRng::seed_from_u64(2));

    let tree1: HidingTree<_> = config1.build_tree(matrices1);
    let tree2: HidingTree<_> = config2.build_tree(matrices2);

    assert_ne!(tree1.root(), tree2.root());
}

#[test]
fn open_batch_handles_empty_or_oob() {
    let mut rng = SmallRng::seed_from_u64(7);
    let lmcs = lmcs();
    let matrices = vec![RowMajorMatrix::rand(&mut rng, 4, 3)];
    let tree = lmcs.build_tree(matrices);
    let widths = tree.widths();
    let log_max_height = log2_strict_u8(tree.height());
    let commitment = tree.root();

    let (prover_digest, transcript) = gl::prover_channel().finalize();

    assert_eq!(
        verify_open_batch(
            &lmcs,
            &commitment,
            &widths,
            log_max_height,
            &[],
            &transcript,
            &prover_digest,
        ),
        Err(LmcsError::InvalidProof)
    );

    assert_eq!(
        verify_open_batch(
            &lmcs,
            &commitment,
            &widths,
            log_max_height,
            &[tree.height()],
            &transcript,
            &prover_digest,
        ),
        Err(LmcsError::InvalidProof)
    );
}

#[test]
fn build_tree_alignment_modes() {
    let mut rng = SmallRng::seed_from_u64(123);
    let lmcs = lmcs();
    let matrices = vec![
        RowMajorMatrix::rand(&mut rng, 4, 3),
        RowMajorMatrix::rand(&mut rng, 8, 5),
    ];

    let tree_unaligned = lmcs.build_tree(matrices.clone());
    let tree_aligned = lmcs.build_aligned_tree(matrices);
    let alignment = tree_aligned.alignment();
    let expected_alignment = <Sponge as Alignable<F, F>>::ALIGNMENT;

    assert_eq!(tree_unaligned.alignment(), 1);
    assert_eq!(alignment, expected_alignment);
    assert_eq!(tree_unaligned.root(), tree_aligned.root());

    let widths_aligned = tree_aligned.widths();
    assert_eq!(widths_aligned[0], aligned_len(3, expected_alignment));
    assert_eq!(widths_aligned[1], aligned_len(5, expected_alignment));

    let widths_unaligned = tree_unaligned.widths();
    assert_eq!(widths_unaligned, vec![3, 5]);
    if expected_alignment > 1 {
        assert_ne!(widths_unaligned, widths_aligned);
    }

    let rows_aligned = tree_aligned.rows(0);
    let widths_a: Vec<usize> = rows_aligned.iter_rows().map(|r| r.len()).collect();
    assert_eq!(widths_a, widths_aligned);

    let rows_unaligned = tree_unaligned.rows(0);
    let widths_u: Vec<usize> = rows_unaligned.iter_rows().map(|r| r.len()).collect();
    assert_eq!(widths_u, widths_unaligned);

    let indices = [0usize, 1usize];
    let (_transcript, opened_rows) = roundtrip_open_batch(&lmcs, &tree_aligned, &indices)
        .expect("aligned opening should verify");
    for (&idx, rows) in &opened_rows {
        assert_eq!(*rows, tree_aligned.rows(idx));
    }
}

#[test]
fn batch_proof_handles_empty_or_oob() {
    let mut rng = SmallRng::seed_from_u64(9);
    let lmcs = lmcs();
    let matrices = vec![RowMajorMatrix::rand(&mut rng, 4, 3)];
    let tree = lmcs.build_tree(matrices);
    let widths = tree.widths();
    let log_max_height = log2_strict_u8(tree.height());

    let mut prover_channel = gl::prover_channel();
    tree.prove_batch([0], &mut prover_channel);
    let (_, transcript) = prover_channel.finalize();

    let mut verifier_channel = gl::verifier_channel(&transcript);
    let batch = BatchProof::<F, Commitment>::read_from_channel(
        &widths,
        log_max_height,
        &[],
        &mut verifier_channel,
    )
    .unwrap();
    assert!(batch.openings.is_empty());
    assert!(batch.siblings.is_empty());
    let proofs = batch.single_proofs(&lmcs, &widths, log_max_height).unwrap();
    assert!(proofs.is_empty());

    let mut verifier_channel = gl::verifier_channel(&transcript);
    let batch = BatchProof::<F, Commitment>::read_from_channel(
        &[],
        log_max_height,
        &[0],
        &mut verifier_channel,
    )
    .unwrap();
    let proofs = batch.single_proofs(&lmcs, &[], log_max_height).unwrap();
    assert_eq!(proofs.len(), 1);
    let proof = proofs.get(&0).expect("proof for index 0");
    let Proof {
        rows,
        salt,
        siblings,
    } = proof;
    assert_eq!(rows.num_rows(), 0);
    assert!(salt.is_empty());
    assert_eq!(siblings.len(), 2);

    // Out-of-range indices are not rejected at parse time; they produce proofs that
    // fail verification. Here we just confirm parsing succeeds (verification tested elsewhere).
    let mut verifier_channel = gl::verifier_channel(&transcript);
    let _ = BatchProof::<F, Commitment>::read_from_channel(
        &widths,
        log_max_height,
        &[tree.height()],
        &mut verifier_channel,
    )
    .unwrap();
}
