//! Batch-STARK benchmark with a dummy Miden-shaped AIR on Goldilocks + Poseidon2.
//!
//! Two traces: 51 columns at 2^18 and 20 columns at 2^19, degree-9 constraint
//! (8 quotient chunks), 8 local lookups producing 8 EF permutation columns.
//! Prints a tracing span tree for comparison against the lifted prover.
//!
//! ```bash
//! BENCH_ITERS=3 RUST_LOG=debug RUSTFLAGS="-C target-cpu=native" \
//!   cargo run -p p3-miden-lifted-examples --release --features parallel --bin batch_miden
//! ```

use p3_air::{Air, AirBuilder, AirLayout, BaseAir, BaseLeaf, SymbolicExpression, WindowAccess};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_lookup::{
    LookupAir,
    lookup_traits::{Direction, Kind, Lookup},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::goldilocks_poseidon2 as gl;
use p3_miden_lifted_examples::{
    miden::{
        TRACE1_LOG_HEIGHT, TRACE1_WIDTH, TRACE2_LOG_HEIGHT, TRACE2_WIDTH, generate_dummy_trace,
    },
    stats,
    stats::{bench_iters, init_tracing},
};
use p3_symmetric::PaddingFreeSponge;
use p3_uni_stark::SymbolicAirBuilder;
use tracing::info_span;

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;

const LOG_BLOWUP: usize = 3;
const NUM_QUERIES: usize = 100;
const POW_BITS: usize = 16;

/// Number of local lookups per AIR (produces 8 EF permutation columns).
const NUM_LOOKUPS: usize = 8;

// ---------------------------------------------------------------------------
// AIR wrapper with lookups for batch-STARK
// ---------------------------------------------------------------------------

/// Wraps `DummyMidenAir` constraints
/// and adds `NUM_LOOKUPS` local lookups, each producing one EF permutation column.
#[derive(Clone)]
struct MidenWithLookups {
    width: usize,
    num_lookups: usize,
}

impl MidenWithLookups {
    fn new(width: usize) -> Self {
        Self {
            width,
            num_lookups: 0,
        }
    }
}

impl<F> BaseAir<F> for MidenWithLookups {
    fn width(&self) -> usize {
        self.width
    }
}

impl<AB: AirBuilder> Air<AB> for MidenWithLookups {
    fn eval(&self, builder: &mut AB) {
        // Same degree-9 constraint as DummyMidenAir.
        let main = builder.main();
        let local = main.current_slice();
        let product = (0..9).fold(AB::Expr::ONE, |acc, j| acc * local[j].into());
        builder.assert_zero(product);
    }
}

impl<F: Field> LookupAir<F> for MidenWithLookups {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: self.width,
            ..AirLayout::default()
        });
        let main = symbolic.main();
        let local = main.current_slice();
        let col0: SymbolicExpression<F> = local[0].into();

        let one = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let lookup_inputs = vec![
            (vec![col0.clone()], one.clone(), Direction::Send),
            (vec![col0], one, Direction::Receive),
        ];

        (0..NUM_LOOKUPS)
            .map(|_| LookupAir::register_lookup(self, Kind::Local, &lookup_inputs))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Perm = gl::Perm;
type MmcsSponge = PaddingFreeSponge<Perm, { gl::WIDTH }, { gl::RATE }, { gl::DIGEST }>;
type Compress = gl::Compress;
type ValMmcs = MerkleTreeMmcs<gl::P, gl::P, MmcsSponge, Compress, 2, { gl::DIGEST }>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type BatchPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type BatchChallenger = DuplexChallenger<Val, Perm, { gl::WIDTH }, { gl::RATE }>;
type BatchConfig = p3_uni_stark::StarkConfig<BatchPcs, Challenge, BatchChallenger>;

fn batch_config() -> BatchConfig {
    let (perm, _, compress) = gl::test_components();
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
    let stats_handle = init_tracing();
    let bench_iters = bench_iters();

    let config = batch_config();

    // --- Generate traces ---
    let trace1: RowMajorMatrix<Val> = info_span!(
        "generate trace 1",
        width = TRACE1_WIDTH,
        log_height = TRACE1_LOG_HEIGHT
    )
    .in_scope(|| generate_dummy_trace(TRACE1_WIDTH, TRACE1_LOG_HEIGHT));

    let trace2: RowMajorMatrix<Val> = info_span!(
        "generate trace 2",
        width = TRACE2_WIDTH,
        log_height = TRACE2_LOG_HEIGHT
    )
    .in_scope(|| generate_dummy_trace(TRACE2_WIDTH, TRACE2_LOG_HEIGHT));

    tracing::info!(
        trace1_height = trace1.height(),
        trace1_width = trace1.width(),
        trace2_height = trace2.height(),
        trace2_width = trace2.width(),
        "trace dims"
    );

    let mut airs = [
        MidenWithLookups::new(TRACE1_WIDTH),
        MidenWithLookups::new(TRACE2_WIDTH),
    ];
    let prover_data = ProverData::from_airs_and_degrees(
        &config,
        &mut airs,
        &[TRACE1_LOG_HEIGHT as usize, TRACE2_LOG_HEIGHT as usize],
    );
    let common = &prover_data.common;
    let traces = [&trace1, &trace2];
    let pvs: Vec<Vec<Val>> = vec![vec![], vec![]];

    for i in 0..=bench_iters {
        if i == 0 {
            tracing::info!("warm-up iteration");
        } else {
            tracing::info!(iteration = i, total = bench_iters, "bench iteration");
        }

        let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);

        let proof = info_span!("prove").in_scope(|| prove_batch(&config, &instances, &prover_data));

        if i == 1 {
            let size = stats::serialized_size(&proof);
            println!("proof size: {}", stats::format_bytes(size));
        }

        info_span!("verify").in_scope(|| {
            verify_batch(&config, &airs, &proof, &pvs, common)
                .expect("batch-stark verification failed");
        });

        if i == 0 {
            stats_handle.clear();
        }
    }

    stats_handle.print_summary();
}
