//! PCS comparison benchmarks: Lifted PCS vs Workspace TwoAdicFriPcs.
//!
//! Compares the complete open operation for both PCS implementations
//! using multiple trace groups with different heights (simulating real STARK scenarios).
//!
//! Setup uses `RELATIVE_SPECS` from bench_utils which defines 3 groups:
//! - Group 0: Main trace columns at various heights
//! - Group 1: Auxiliary/permutation columns
//! - Group 2: Quotient polynomial chunks
//!
//! Runs benchmarks for Goldilocks with Poseidon2.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench pcs --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench pcs --features testing,parallel
//!
//! # Filter by field
//! cargo bench --bench pcs --features testing -- goldilocks
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::{
    LOG_HEIGHTS, RELATIVE_SPECS,
    configs::goldilocks_poseidon2::{
        Challenger, Compress, DIGEST, EF, F, P, Perm, RATE, WIDTH, create_perm, test_challenger,
    },
    generate_matrices_from_specs, total_elements,
};
use p3_miden_lifted_fri::{PcsParams, prover as lifted_prover};
use p3_miden_lmcs::{Lmcs, LmcsTree, log2_strict_u8, testing::goldilocks_poseidon2::test_lmcs};
use p3_miden_transcript::ProverTranscript;
use p3_symmetric::PaddingFreeSponge;

// =============================================================================
// Constants
// =============================================================================

/// Log blowup factor for FRI.
const LOG_BLOWUP: usize = 2;

/// Number of FRI queries.
const NUM_QUERIES: usize = 30;

/// Log degree of final polynomial.
const LOG_FINAL_DEGREE: usize = 8;

/// Maximum log arity for FRI.
const MAX_LOG_ARITY: usize = 1;

const PARALLEL_STR: &str = if cfg!(feature = "parallel") {
    "parallel"
} else {
    "single"
};

// =============================================================================
// Types
// =============================================================================

type Dft = Radix2DitParallel<F>;
type MmcsSponge = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>;
type ValMmcs = MerkleTreeMmcs<P, P, MmcsSponge, Compress, 2, DIGEST>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type WorkspacePcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;

// =============================================================================
// Entry point
// =============================================================================

fn bench_pcs(c: &mut Criterion) {
    let dft = Dft::default();
    let shift = F::GENERATOR;

    for &log_lde_height in LOG_HEIGHTS {
        let max_lde_size = 1usize << log_lde_height;
        let group_name = format!(
            "PCS_Open/{}/goldilocks/poseidon2/{}",
            max_lde_size, PARALLEL_STR
        );
        let mut group = c.benchmark_group(&group_name);

        // Generate test matrices
        let matrix_groups: Vec<Vec<RowMajorMatrix<F>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_lde_height);
        group.throughput(Throughput::Elements(total_elements(&matrix_groups)));

        // =============================================================
        // Workspace TwoAdicFriPcs benchmark
        // =============================================================
        {
            let perm = create_perm();
            let mmcs_sponge = MmcsSponge::new(perm.clone());
            let compress = Compress::new(perm);
            let val_mmcs = ValMmcs::new(mmcs_sponge, compress, 0);
            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
            let fri_params = FriParameters {
                log_blowup: LOG_BLOWUP,
                log_final_poly_len: LOG_FINAL_DEGREE,
                max_log_arity: MAX_LOG_ARITY,
                num_queries: NUM_QUERIES,
                commit_proof_of_work_bits: 0,
                query_proof_of_work_bits: 0,
                mmcs: challenge_mmcs,
            };
            let workspace_pcs = WorkspacePcs::new(Dft::default(), val_mmcs, fri_params);

            let commits_and_data: Vec<_> = matrix_groups
                .iter()
                .map(|matrices| {
                    let domains_and_evals = matrices.iter().map(|m| {
                        let domain =
                            <WorkspacePcs as Pcs<EF, Challenger>>::natural_domain_for_degree(
                                &workspace_pcs,
                                m.height(),
                            );
                        (domain, m.clone())
                    });
                    <WorkspacePcs as Pcs<EF, Challenger>>::commit(&workspace_pcs, domains_and_evals)
                })
                .collect();

            let base_challenger = test_challenger();

            group.bench_function(BenchmarkId::from_parameter("workspace"), |b| {
                b.iter(|| {
                    let mut challenger = base_challenger.clone();
                    for (commitment, _) in &commits_and_data {
                        challenger.observe(commitment.clone());
                    }
                    let z1: EF = challenger.sample_algebra_element();
                    let z2: EF = challenger.sample_algebra_element();

                    let data_and_points: Vec<_> = commits_and_data
                        .iter()
                        .enumerate()
                        .map(|(i, (_, prover_data))| {
                            let num_matrices = matrix_groups[i].len();
                            let points = if i < 2 {
                                vec![vec![z1, z2]; num_matrices]
                            } else {
                                vec![vec![z1]; num_matrices]
                            };
                            (prover_data, points)
                        })
                        .collect();

                    let (_openings, proof) = <WorkspacePcs as Pcs<EF, Challenger>>::open(
                        &workspace_pcs,
                        black_box(data_and_points),
                        &mut challenger,
                    );
                    black_box(proof)
                });
            });
        }

        // =============================================================
        // Lifted PCS benchmarks (arity 2 and 4)
        // =============================================================
        // Note: Lifted PCS uses a single tree for all matrices, so we
        // flatten all matrix groups into a single tree for fair comparison.
        {
            let lmcs = test_lmcs();

            // Compute LDE matrices and flatten into a single group (sorted by height)
            let mut all_lde_matrices: Vec<_> = matrix_groups
                .iter()
                .flat_map(|matrices| {
                    matrices
                        .iter()
                        .map(|m| dft.coset_lde_batch(m.clone(), LOG_BLOWUP, shift))
                })
                .collect();
            // Sort by height (ascending) as required by LMCS
            all_lde_matrices.sort_by_key(|m| m.height());

            // Build a single LMCS tree with all matrices
            let tree = lmcs.build_aligned_tree(all_lde_matrices);
            let commitment = tree.root();
            let log_lde_height = log2_strict_u8(tree.height());

            let base_challenger = test_challenger();

            for (name, log_folding_arity) in [("lifted/arity2", 1u8), ("lifted/arity4", 2u8)] {
                let params = PcsParams::new(
                    LOG_BLOWUP as u8,
                    log_folding_arity,
                    LOG_FINAL_DEGREE as u8,
                    0, // folding_pow_bits
                    0, // deep_pow_bits
                    NUM_QUERIES,
                    0, // query_pow_bits
                )
                .expect("valid PCS params");

                group.bench_function(BenchmarkId::from_parameter(name), |b| {
                    b.iter(|| {
                        let mut challenger = base_challenger.clone();
                        challenger.observe(commitment);
                        let z1: EF = challenger.sample_algebra_element();
                        let z2: EF = challenger.sample_algebra_element();
                        let mut channel = ProverTranscript::new(challenger);

                        // Wrap single tree in slice for multi-tree API
                        let trace_trees: &[&_] = &[&tree];
                        lifted_prover::open_with_channel::<F, EF, _, _, _, 2>(
                            &params,
                            &lmcs,
                            log_lde_height,
                            [z1, z2],
                            trace_trees,
                            &mut channel,
                        );
                        black_box(channel.finalize())
                    });
                });
            }
        }

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_pcs
}
criterion_main!(benches);
