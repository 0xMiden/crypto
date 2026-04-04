//! Microbenchmark: lifted `commit_quotient` vs Plonky3 PCS `commit_quotient`.
//!
//! Both commit the same-shaped random quotient evaluations (N*D extension field
//! values) to a Merkle tree. This isolates the decomposition + LDE + commit
//! pipeline from the rest of proving.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p p3-miden-lifted-stark --bench quotient_commit --features testing
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{Field, coset::TwoAdicMultiplicativeCoset};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::goldilocks_poseidon2::{
    Challenger, Compress, DIGEST, EF, F, P, Perm, RATE, WIDTH, test_challenger, test_components,
};
use p3_miden_lifted_fri::PcsParams;
use p3_miden_lifted_stark::{
    air::log2_strict_u8, coset::LiftedCoset, prover::quotient::commit_quotient,
};
use p3_miden_lmcs::testing::goldilocks_poseidon2 as gl_lmcs;
use p3_symmetric::PaddingFreeSponge;
use rand::{RngExt, SeedableRng, rngs::SmallRng};

// =============================================================================
// Types
// =============================================================================

type Dft = Radix2DitParallel<F>;

// Plonky3 PCS types (baseline)
type MmcsSponge = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>;
type ValMmcs = MerkleTreeMmcs<P, P, MmcsSponge, Compress, 2, DIGEST>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type WorkspacePcs = p3_fri::TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;

// Lifted types
type LiftedLmcs = gl_lmcs::Lmcs;
type LiftedConfig = p3_miden_lifted_stark::GenericStarkConfig<F, EF, LiftedLmcs, Dft, Challenger>;

// =============================================================================
// Constants
// =============================================================================

const LOG_BLOWUP: u8 = 1;
const D: usize = 2; // constraint degree (KeccakAir)

// =============================================================================
// Setup helpers
// =============================================================================

fn lifted_config() -> LiftedConfig {
    let pcs = PcsParams::new(
        LOG_BLOWUP, // log_blowup
        1,          // log_folding_arity (arity 2)
        0,          // log_final_degree
        0,          // folding_pow_bits
        0,          // deep_pow_bits
        1,          // num_queries
        0,          // query_pow_bits
    )
    .expect("valid PCS params");
    let lmcs: LiftedLmcs = gl_lmcs::test_lmcs();
    LiftedConfig::new(pcs, lmcs, Dft::default(), test_challenger())
}

fn workspace_pcs() -> WorkspacePcs {
    let (perm, _, compress) = test_components();
    let mmcs_sponge = MmcsSponge::new(perm);
    let mmcs = ValMmcs::new(mmcs_sponge, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: LOG_BLOWUP as usize,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    WorkspacePcs::new(Dft::default(), mmcs, fri_params)
}

fn random_quotient_evals(n: usize, d: usize, seed: u64) -> Vec<EF> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..n * d).map(|_| rng.random()).collect()
}

// =============================================================================
// Benchmark
// =============================================================================

fn bench_quotient_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("quotient_commit");
    let log_d = log2_strict_u8(D);

    for log_n in [16u8, 17u8] {
        let n = 1usize << log_n;
        let b = 1usize << LOG_BLOWUP;
        let label = format!("N=2^{log_n}");

        // ----- Lifted commit_quotient -----
        {
            let config = lifted_config();
            let coset = LiftedCoset::unlifted(log_n, LOG_BLOWUP);

            group.bench_function(BenchmarkId::new("lifted", &label), |bench| {
                bench.iter(|| {
                    let mut q_evals = random_quotient_evals(n, D, 42);
                    q_evals.reserve(n * b - n * D);
                    let committed = commit_quotient(&config, q_evals, &coset);
                    black_box(committed)
                });
            });
        }

        // ----- Plonky3 PCS commit_quotient -----
        {
            let pcs = workspace_pcs();
            let quotient_domain =
                TwoAdicMultiplicativeCoset::new(F::GENERATOR, (log_n + log_d) as usize).unwrap();

            group.bench_function(BenchmarkId::new("plonky3_pcs", &label), |bench| {
                bench.iter(|| {
                    let q_evals = random_quotient_evals(n, D, 42);
                    let q_flat = RowMajorMatrix::new_col(q_evals).flatten_to_base();
                    let (commitment, data) = <WorkspacePcs as Pcs<EF, Challenger>>::commit_quotient(
                        &pcs,
                        quotient_domain,
                        q_flat,
                        D,
                    );
                    black_box((commitment, data))
                });
            });
        }
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_quotient_commit
}
criterion_main!(benches);
