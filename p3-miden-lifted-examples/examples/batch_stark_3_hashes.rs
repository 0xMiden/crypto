//! Batch-STARK benchmark: three different hash AIRs (Poseidon2, Keccak, Blake3)
//! at heights 2^19, 2^18, and 2^15 respectively — no lookups.
//! Prints a tracing span tree for comparison against the lifted prover.
//!
//! Set `BENCH_ITERS` to control the number of measured iterations (default: 5).
//! The first iteration is a warm-up (tracing tree printed, stats discarded).
//!
//! ```bash
//! RUST_LOG=debug cargo run -p p3-miden-lifted-examples --release --features parallel --bin batch_stark_3_hashes
//! ```

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_blake3_air::{Blake3Air, NUM_BLAKE3_COLS};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS};
use p3_lookup::{Lookup, LookupAir};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::baby_bear_poseidon2 as bb;
use p3_miden_lifted_examples::{
    blake3::generate_blake3_trace,
    keccak::generate_keccak_trace,
    poseidon2::{
        HALF_FULL_ROUNDS, NUM_POSEIDON2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS, WIDTH,
        generate_poseidon2_trace,
    },
    stats,
    stats::StatsLayer,
};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::PaddingFreeSponge;
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use tracing::info_span;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Layer as _, Registry, layer::SubscriberExt, util::SubscriberInitExt,
};

// Blake3: 2^15 rows, 1 row/hash → 32768 hashes (widest, shortest).
const NUM_BLAKE3_HASHES: usize = 32768;
// Keccak: 2^18 rows, 24 rows/hash → floor(262144/24) = 10922 hashes.
const NUM_KECCAK_HASHES: usize = 10922;
// Poseidon2: 2^19 rows, 1 row/hash → 524288 hashes (narrowest, tallest).
const NUM_POSEIDON2_HASHES: usize = 524288;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

const LOG_BLOWUP: usize = 1;
const NUM_QUERIES: usize = 100;
const POW_BITS: usize = 16;

// ─── Enum wrapper for heterogeneous AIRs ─────────────────────────────────────

type InnerPoseidon2Air = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

#[derive(Clone)]
enum HashAir {
    Poseidon2(Box<InnerPoseidon2Air>),
    Keccak,
    Blake3,
}

impl<F> BaseAir<F> for HashAir {
    fn width(&self) -> usize {
        match self {
            Self::Poseidon2(_) => NUM_POSEIDON2_COLS,
            Self::Keccak => NUM_KECCAK_COLS,
            Self::Blake3 => NUM_BLAKE3_COLS,
        }
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for HashAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Poseidon2(inner) => Air::eval(inner.as_ref(), builder),
            Self::Keccak => Air::eval(&KeccakAir {}, builder),
            Self::Blake3 => Air::eval(&Blake3Air {}, builder),
        }
    }
}

/// Skip defining lookups for these AIRs.
impl<F: Field> LookupAir<F> for HashAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Poseidon2(_) => vec![],
            Self::Keccak => vec![],
            Self::Blake3 => vec![],
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Poseidon2(_) => vec![],
            Self::Keccak => vec![],
            Self::Blake3 => vec![],
        }
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
    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing_forest::util::LevelFilter::DEBUG.into())
        .from_env_lossy();

    let stats = StatsLayer::new();
    let stats_handle = stats.handle();

    // Apply env filter only to ForestLayer so StatsLayer always sees all spans.
    Registry::default()
        .with(ForestLayer::default().with_filter(env_filter))
        .with(stats)
        .init();

    let bench_iters: usize = std::env::var("BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let config = batch_config();

    let mut rng = SmallRng::seed_from_u64(1);

    // --- Poseidon2 trace (2^19) ---
    let poseidon2_constants = RoundConstants::from_rng(&mut rng);
    let poseidon2_inputs: Vec<[Val; 16]> =
        (0..NUM_POSEIDON2_HASHES).map(|_| rng.random()).collect();
    let trace_poseidon2: RowMajorMatrix<Val> =
        info_span!("generate Poseidon2 trace", hashes = NUM_POSEIDON2_HASHES)
            .in_scope(|| generate_poseidon2_trace(poseidon2_inputs, &poseidon2_constants));

    // --- Keccak trace (2^18) ---
    let keccak_inputs: Vec<[u64; 25]> = (0..NUM_KECCAK_HASHES).map(|_| rng.random()).collect();
    let trace_keccak: RowMajorMatrix<Val> =
        info_span!("generate Keccak trace", hashes = NUM_KECCAK_HASHES)
            .in_scope(|| generate_keccak_trace(keccak_inputs));

    // --- Blake3 trace (2^15) ---
    let blake3_inputs: Vec<[u32; 24]> = (0..NUM_BLAKE3_HASHES).map(|_| rng.random()).collect();
    let trace_blake3: RowMajorMatrix<Val> =
        info_span!("generate Blake3 trace", hashes = NUM_BLAKE3_HASHES)
            .in_scope(|| generate_blake3_trace(blake3_inputs));

    tracing::info!(
        poseidon2_height = trace_poseidon2.height(),
        poseidon2_width = trace_poseidon2.width(),
        keccak_height = trace_keccak.height(),
        keccak_width = trace_keccak.width(),
        blake3_height = trace_blake3.height(),
        blake3_width = trace_blake3.width(),
        "trace dims"
    );

    let air_poseidon2 = HashAir::Poseidon2(Box::new(InnerPoseidon2Air::new(poseidon2_constants)));
    let air_keccak = HashAir::Keccak;
    let air_blake3 = HashAir::Blake3;
    let mut airs: [HashAir; 3] = [air_poseidon2, air_keccak, air_blake3];
    let degree_bits = [19, 18, 15];
    let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &degree_bits);
    let common = &prover_data.common;
    let traces = [&trace_poseidon2, &trace_keccak, &trace_blake3];
    let pvs: Vec<Vec<Val>> = vec![vec![], vec![], vec![]];

    // Run iterations: iteration 0 is warm-up (tracing tree printed, stats discarded).
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
            std::println!("proof size: {}", stats::format_bytes(size));
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
