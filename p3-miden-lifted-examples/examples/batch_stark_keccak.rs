//! Batch-STARK benchmark: 3x KeccakAir at heights 2^15, 2^18, and 2^19, each with a
//! single local LogUp lookup producing one EF permutation column (= 4 base-field
//! columns). Prints a tracing span tree for comparison against the lifted prover.
//!
//! The per-instance lookup matches the lifted prover's unconditional 1-column EF
//! aux trace. The lookup is trivially satisfiable: column 0 is both sent and
//! received with multiplicity 1, so the running sum is always zero.
//!
//! ```bash
//! cargo run -p p3-miden-lifted-examples --release --bin batch_stark_keccak
//! ```

use p3_air::{Air, AirBuilder, BaseAir, BaseLeaf, SymbolicExpression};
use p3_baby_bear::BabyBear;
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak_air::{KeccakAir, generate_trace_rows};
use p3_lookup::{
    LookupAir,
    lookup_traits::{Direction, Kind, Lookup},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::baby_bear_poseidon2 as bb;
use p3_miden_lifted_examples::stats;
use p3_symmetric::PaddingFreeSponge;
use p3_util::log2_strict_usize;
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use tracing::info_span;

// Trace S: 2^15 rows -> floor(32768/24) = 1365 hashes.
const NUM_HASHES_S: usize = 1365;
// Trace A: 2^18 rows -> floor(262144/24) = 10922 hashes.
const NUM_HASHES_A: usize = 10922;
// Trace B: 2^19 rows -> floor(524288/24) = 21845 hashes.
const NUM_HASHES_B: usize = 21845;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

const LOG_BLOWUP: usize = 1;
const NUM_QUERIES: usize = 100;
const POW_BITS: usize = 16;

// ─── KeccakAir wrapper with a single local lookup ────────────────────────────

/// Wraps [`KeccakAir`] and adds a single local LogUp lookup, producing one
/// extension-field permutation column (= 4 base-field columns). This matches
/// the lifted prover's unconditional 1-column EF aux trace.
///
/// The lookup reads column 0 with Send and Receive directions at every row,
/// making the running sum trivially zero.
#[derive(Debug, Clone)]
struct KeccakWithLookup {
    num_lookups: usize,
}

impl KeccakWithLookup {
    fn new() -> Self {
        Self { num_lookups: 0 }
    }
}

impl<F> BaseAir<F> for KeccakWithLookup {
    fn width(&self) -> usize {
        BaseAir::<F>::width(&KeccakAir {})
    }
}

impl<AB: AirBuilder> Air<AB> for KeccakWithLookup {
    fn eval(&self, builder: &mut AB) {
        Air::eval(&KeccakAir {}, builder);
    }
}

impl<F: Field> LookupAir<F> for KeccakWithLookup {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;
        let col0 = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let one = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let lookup_inputs = vec![
            (vec![col0.clone()], one.clone(), Direction::Send),
            (vec![col0], one, Direction::Receive),
        ];
        vec![LookupAir::register_lookup(
            self,
            Kind::Local,
            &lookup_inputs,
        )]
    }
}

// ─── Config ──────────────────────────────────────────────────────────────────

type Perm = bb::Perm;
type MmcsSponge = PaddingFreeSponge<Perm, { bb::WIDTH }, { bb::RATE }, { bb::DIGEST }>;
type Compress = bb::Compress;
type ValMmcs = MerkleTreeMmcs<bb::P, bb::P, MmcsSponge, Compress, 2, { bb::DIGEST }>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type BatchPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type BatchChallenger = DuplexChallenger<Val, Perm, { bb::WIDTH }, { bb::RATE }>;
type BatchConfig = p3_uni_stark::StarkConfig<BatchPcs, Challenge, BatchChallenger>;

fn batch_config() -> BatchConfig {
    let (perm, _, compress) = bb::test_components();
    let mmcs_sponge = MmcsSponge::new(perm.clone());
    let mmcs = ValMmcs::new(mmcs_sponge, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: POW_BITS,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let dft = Dft::default();
    let pcs = BatchPcs::new(dft, mmcs, fri_params);
    let challenger = BatchChallenger::new(perm);
    BatchConfig::new(pcs, challenger)
}

fn main() {
    let stats_handle = stats::init_tracing();
    let bench_iters = stats::bench_iters();

    let config = batch_config();

    let mut rng = SmallRng::seed_from_u64(1);
    let inputs_s: Vec<[u64; 25]> = (0..NUM_HASHES_S).map(|_| rng.random()).collect();
    let inputs_a: Vec<[u64; 25]> = (0..NUM_HASHES_A).map(|_| rng.random()).collect();
    let inputs_b: Vec<[u64; 25]> = (0..NUM_HASHES_B).map(|_| rng.random()).collect();

    let trace_s: RowMajorMatrix<Val> = info_span!("generate trace S", hashes = NUM_HASHES_S)
        .in_scope(|| generate_trace_rows(inputs_s, LOG_BLOWUP));
    let trace_a: RowMajorMatrix<Val> = info_span!("generate trace A", hashes = NUM_HASHES_A)
        .in_scope(|| generate_trace_rows(inputs_a, LOG_BLOWUP));
    let trace_b: RowMajorMatrix<Val> = info_span!("generate trace B", hashes = NUM_HASHES_B)
        .in_scope(|| generate_trace_rows(inputs_b, LOG_BLOWUP));

    let height_s = trace_s.height();
    let height_a = trace_a.height();
    let height_b = trace_b.height();
    let log_height_s = log2_strict_usize(height_s);
    let log_height_a = log2_strict_usize(height_a);
    let log_height_b = log2_strict_usize(height_b);

    tracing::info!(
        height_s,
        height_a,
        height_b,
        width = trace_a.width(),
        "trace dims"
    );

    for i in 0..=bench_iters {
        if i == 0 {
            tracing::info!("warm-up iteration");
        } else {
            tracing::info!(iteration = i, total = bench_iters, "bench iteration");
        }

        let mut airs = [
            KeccakWithLookup::new(),
            KeccakWithLookup::new(),
            KeccakWithLookup::new(),
        ];
        let prover_data = ProverData::from_airs_and_degrees(
            &config,
            &mut airs,
            &[log_height_s, log_height_a, log_height_b],
        );
        let common = &prover_data.common;

        let traces = [&trace_s, &trace_a, &trace_b];

        let instances =
            StarkInstance::new_multiple(&airs, &traces, &[vec![], vec![], vec![]], common);

        let proof = info_span!("prove").in_scope(|| prove_batch(&config, &instances, &prover_data));

        if i == 1 {
            let size = stats::serialized_size(&proof);
            println!("proof size: {}", stats::format_bytes(size));
        }

        info_span!("verify").in_scope(|| {
            let pvs: Vec<Vec<Val>> = vec![vec![], vec![], vec![]];
            verify_batch(&config, &airs, &proof, &pvs, common)
                .expect("batch-stark verification failed");
        });

        if i == 0 {
            stats_handle.clear();
        }
    }

    stats_handle.print_summary();
}
