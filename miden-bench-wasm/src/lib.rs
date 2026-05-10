//! WASM benchmarks for the public hash primitives.
//!
//! Each `bench_*` function is exported via `wasm-bindgen` and invoked by the
//! Playwright driver from JS. The function:
//!   1. Constructs the bench's input data (deterministic seeded RNG).
//!   2. Runs `warmup_iterations` un-timed iterations to settle the V8 JIT.
//!   3. Runs `num_batches` batches of `batch_size` iterations each, timed via `performance.now()`
//!      per batch (post-Spectre, single-iter timing is too coarse — batching amortizes timer
//!      noise).
//!   4. Returns a `Vec<f64>` of per-iteration times in nanoseconds, one entry per batch.
//!
//! The driver computes median + IQR + p99 across the batches.
//!
//! # Iteration tuning
//!
//! Pick `batch_size` so each batch is ~5–10 ms. For RPO/RPX/Poseidon2 merge
//! ops at ~2-5 µs/op in WASM, that's ~1500–4000 iterations per batch. The
//! driver passes these from JS so we can tune without rebuilding the WASM.
//!
//! # Why single-thread + no SAB
//!
//! These are pure compute, no `SharedArrayBuffer`, no rayon, no Workers. So
//! the bench page does NOT need COOP/COEP — that's the part of the wallet's
//! prove harness that's flaky. Skipping it makes CI fast and stable.

use miden_crypto::{
    Felt,
    hash::{
        HasherExt,
        blake::Blake3_256,
        keccak::Keccak256,
        poseidon2::{Poseidon2, Poseidon2Permutation256},
        rpo::{Rpo256, RpoPermutation256},
        rpx::{Rpx256, RpxPermutation256},
    },
};
// Prove-bench types live in lifted-stark's `testing::configs::Felt` (=
// `p3_goldilocks::Goldilocks`), which is *distinct* from
// `miden_crypto::Felt` (a wrapper struct around Goldilocks). Aliased here
// to make the difference explicit at call sites.
use miden_lifted_stark::{
    AirWitness, GenericStarkConfig, PcsParams, prove_multi,
    testing::{
        airs::{ZeroAuxBuilder, blake3::LiftedBlake3Air},
        configs::{Felt as StarkFelt, QuadFelt as StarkQuadFelt, goldilocks_blake3},
    },
};
use p3_blake3_air::generate_trace_rows as generate_blake3_air_trace;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use wasm_bindgen::prelude::*;

// Stable seed so PR-time runs and baseline runs use byte-identical input
// data. Without this, run-to-run noise from input randomness would dwarf
// the perf signal we're trying to track.
const SEED: u64 = 0x4d_69_64_65_6e_2d_43_50; // "Miden-CP" in ASCII

// Helpers ----------------------------------------------------------------

/// Generates a `[u8; 32]` from the seeded RNG. Used as input to byte-oriented
/// hashes (Blake3, Keccak) before measuring `merge`.
fn make_bytes(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut buf = [0u8; 32];
    rng.fill(&mut buf);
    buf
}

/// Generates a `Vec<Felt>` of length `count` from the seeded RNG. Used as
/// input to `hash_elements` benches. Uses `Felt::new_unchecked` (no reduction
/// check) to match the existing native benches in `miden-crypto/benches/
/// common/data.rs::generate_felt_array_random` — bench inputs are stable
/// across runs from the seed, so a once-validated input set is preserved
/// run-to-run regardless of constructor.
fn make_felts(rng: &mut ChaCha20Rng, count: usize) -> Vec<Felt> {
    (0..count).map(|_| Felt::new_unchecked(rng.random::<u64>())).collect()
}

/// Run `num_batches` × `batch_size` iterations of `f`, returning per-iteration
/// nanoseconds for each batch. `warmup` un-timed iterations precede the
/// measured runs to settle V8's JIT.
fn run_batched<F>(num_batches: u32, batch_size: u32, warmup: u32, mut f: F) -> Vec<f64>
where
    F: FnMut(),
{
    let perf = web_sys::window().expect("no window").performance().expect("no performance");

    for _ in 0..warmup {
        f();
    }

    let mut samples = Vec::with_capacity(num_batches as usize);
    for _ in 0..num_batches {
        let t0 = perf.now();
        for _ in 0..batch_size {
            f();
        }
        let elapsed_ms = perf.now() - t0;
        // Convert ms (performance.now()) → ns/iter, the unit
        // benchmark-action/github-action-benchmark expects.
        samples.push(elapsed_ms * 1_000_000.0 / batch_size as f64);
    }
    samples
}

// Bench functions --------------------------------------------------------

// One macro per bench shape. The closure for input setup is a `fn`-style
// item passed by name (no closure-in-macro-arg ambiguity that way), with
// each algo's `_init` helper spelled out below. Cost vs full inlining: a
// dozen extra lines, paid once at bench setup — not in the timed loop.
macro_rules! bench_merge {
    ($name:ident, $hasher:ty, $init:ident) => {
        #[wasm_bindgen]
        pub fn $name(num_batches: u32, batch_size: u32, warmup: u32) -> Vec<f64> {
            let mut rng = ChaCha20Rng::seed_from_u64(SEED);
            let input = $init(&mut rng);
            run_batched(num_batches, batch_size, warmup, || {
                core::hint::black_box(<$hasher>::merge(core::hint::black_box(&input)));
            })
        }
    };
}

macro_rules! bench_sequential {
    ($name:ident, $hasher:ty, $count:expr) => {
        #[wasm_bindgen]
        pub fn $name(num_batches: u32, batch_size: u32, warmup: u32) -> Vec<f64> {
            let mut rng = ChaCha20Rng::seed_from_u64(SEED);
            let elements = make_felts(&mut rng, $count);
            run_batched(num_batches, batch_size, warmup, || {
                core::hint::black_box(<$hasher>::hash_elements(core::hint::black_box(&elements)));
            })
        }
    };
}

// Per-algo input setup: produce two algo-native digests by hashing 32 random
// bytes each. Spelled out per-algo because the digest type differs across
// hashers (Word for the algebraic ones, Digest256 for byte hashes).
fn rpo256_merge_init(rng: &mut ChaCha20Rng) -> [miden_crypto::Word; 2] {
    [Rpo256::hash(&make_bytes(rng)), Rpo256::hash(&make_bytes(rng))]
}
fn rpx256_merge_init(rng: &mut ChaCha20Rng) -> [miden_crypto::Word; 2] {
    [Rpx256::hash(&make_bytes(rng)), Rpx256::hash(&make_bytes(rng))]
}
fn poseidon2_merge_init(rng: &mut ChaCha20Rng) -> [miden_crypto::Word; 2] {
    [Poseidon2::hash(&make_bytes(rng)), Poseidon2::hash(&make_bytes(rng))]
}
fn blake3_256_merge_init(rng: &mut ChaCha20Rng) -> [<Blake3_256 as HasherExt>::Digest; 2] {
    [Blake3_256::hash(&make_bytes(rng)), Blake3_256::hash(&make_bytes(rng))]
}
fn keccak256_merge_init(rng: &mut ChaCha20Rng) -> [<Keccak256 as HasherExt>::Digest; 2] {
    [Keccak256::hash(&make_bytes(rng)), Keccak256::hash(&make_bytes(rng))]
}

bench_merge!(bench_rpo256_merge, Rpo256, rpo256_merge_init);
bench_sequential!(bench_rpo256_sequential_felt_100, Rpo256, 100);

bench_merge!(bench_rpx256_merge, Rpx256, rpx256_merge_init);
bench_sequential!(bench_rpx256_sequential_felt_100, Rpx256, 100);

bench_merge!(bench_poseidon2_merge, Poseidon2, poseidon2_merge_init);
bench_sequential!(bench_poseidon2_sequential_felt_100, Poseidon2, 100);

bench_merge!(bench_blake3_256_merge, Blake3_256, blake3_256_merge_init);
bench_sequential!(bench_blake3_256_sequential_felt_100, Blake3_256, 100);

bench_merge!(bench_keccak256_merge, Keccak256, keccak256_merge_init);
bench_sequential!(bench_keccak256_sequential_felt_100, Keccak256, 100);

// Packed permutation throughput -----------------------------------------
//
// These exercise the new trait-generic `impl<P: PackedValue<Value = Felt>>
// Permutation<[P; STATE_WIDTH]>` blanket added in 0xMiden/crypto#998.
// The state type is `<Felt as Field>::Packing`, which:
//   - On `next` (no simd128 PR): resolves to `Felt`, WIDTH=1, scalar perm. Numerically identical to
//     the prior concrete impl — the const-folded fast path the PR explicitly preserves.
//   - On #998: resolves to `PackedFelt`, WIDTH=2, two candidates per permutation invocation.
//     Per-call work doubles in throughput.
//
// On the bench dashboard, this metric is unchanged on `next` and steps
// down ~50% the moment #998 lands — making the simd128 win automatically
// visible in CI without bench-source changes.
//
// The merge benches above don't exercise this path (they invoke
// `permute_mut(&mut [Felt; 12])` — WIDTH=1) so they would show 0%
// difference on #998. Both shapes are deliberately tracked.

const STATE_WIDTH: usize = 12;

macro_rules! bench_packed_permute {
    ($name:ident, $perm_ty:ident) => {
        #[wasm_bindgen]
        pub fn $name(num_batches: u32, batch_size: u32, warmup: u32) -> Vec<f64> {
            let perm = $perm_ty;
            let mut rng = ChaCha20Rng::seed_from_u64(SEED);
            // Build a fully-populated state of `<Felt as Field>::Packing`.
            // Each lane gets a distinct value so the perm can't shortcut
            // a uniform-state edge case.
            let mut state = [<Felt as Field>::Packing::ZERO; STATE_WIDTH];
            for slot in &mut state {
                let lane: <Felt as Field>::Packing =
                    <Felt as Field>::Packing::from(Felt::new_unchecked(rng.random::<u64>()));
                *slot = lane;
            }
            run_batched(num_batches, batch_size, warmup, || {
                let mut s = core::hint::black_box(state);
                perm.permute_mut(&mut s);
                core::hint::black_box(s);
            })
        }
    };
}

bench_packed_permute!(bench_rpo256_packed_permute, RpoPermutation256);
bench_packed_permute!(bench_rpx256_packed_permute, RpxPermutation256);
bench_packed_permute!(bench_poseidon2_packed_permute, Poseidon2Permutation256);

// End-to-end synthetic prove --------------------------------------------
//
// Proves a small `LiftedBlake3Air` instance through `miden-lifted-stark`'s
// full pipeline (LDE, constraint folding, DEEP composition, FRI, Merkle
// commits). This is the headline regression-tracking metric: it answers
// "did this PR slow down the actual prove stack?" in one number.
//
// Why Blake3 AIR specifically (vs Keccak / Poseidon2 / Miden VM AIR):
//   - Smallest setup (no round-constants table to thread through).
//   - Already a workspace test fixture (no new code in `miden-lifted-stark`).
//   - Exercises the same arithmetic shape as a real prove: base-field trace, ext-field DEEP/FRI,
//     algebraic-hash-driven LMCS Merkle.
//   - Constraint density is moderate — heavy enough that the constraint- evaluation phase
//     contributes meaningfully to total prove time, so simd128's gain on packed ext-field math will
//     show.
//
// Why log_blowup=1 (vs miden-vm production's 3):
//   - Smaller LDE → faster prove → CI-friendly.
//   - This is a perf-tracking bench, not a security parameter; the proven-soundness number from
//     this config is irrelevant. We just need the same arithmetic shape on every run.
//
// Trace size is parameterised by `log_n` so we can tune CI runtime
// without rebuilding the wasm. Default callers should pass log_n=12
// (4096 hashes) — empirically ~1-3s per prove in WASM, gives a stable
// median across `num_runs` repetitions while staying inside the workflow's
// 15-minute timeout.

#[wasm_bindgen]
pub fn bench_lifted_stark_prove_blake3(num_runs: u32, log_n: u32) -> Vec<f64> {
    let n = 1usize << log_n;
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let inputs: Vec<[u32; 24]> = (0..n)
        .map(|_| {
            let mut row = [0u32; 24];
            for v in &mut row {
                *v = rng.random::<u32>();
            }
            row
        })
        .collect();
    // Trace is built over `StarkFelt` (= Goldilocks), not the wrapper
    // `miden_crypto::Felt`. The prover takes Goldilocks all the way
    // through; the wrapper is for the `miden_crypto::hash` public API.
    let trace: RowMajorMatrix<StarkFelt> = generate_blake3_air_trace(inputs, 0);

    // PCS params calibrated for fast bench runs, NOT production security.
    // log_blowup=1 gives a 2× LDE rather than miden-vm's 8×; combined
    // with no PoW, this minimises wall-clock per prove while still
    // exercising the full pipeline.
    let pcs = PcsParams::new(
        /* log_blowup */ 1, /* log_folding_arity */ 2, /* log_final_degree */ 7,
        /* folding_pow_bits */ 0, /* deep_pow_bits */ 0, /* num_queries */ 27,
        /* query_pow_bits */ 0,
    )
    .expect("invalid PCS params");

    let lmcs = goldilocks_blake3::test_lmcs();
    let dft = Radix2DitParallel::<StarkFelt>::default();
    let challenger_factory = goldilocks_blake3::test_challenger;
    let config: GenericStarkConfig<StarkFelt, StarkQuadFelt, _, _, _> =
        GenericStarkConfig::new(pcs, lmcs, dft, challenger_factory());

    let air = LiftedBlake3Air;
    let aux = ZeroAuxBuilder::dummy();

    let perf = web_sys::window().expect("no window").performance().expect("no performance");
    let mut samples = Vec::with_capacity(num_runs as usize);
    for _ in 0..num_runs {
        // Fresh witness + challenger per run — prove_multi consumes the
        // challenger, and we want byte-identical inputs across runs.
        let witness = AirWitness::new(&trace, &[], &[]);
        let instances = [(&air, witness, &aux)];
        let challenger = challenger_factory();
        let t0 = perf.now();
        let _proof = prove_multi(&config, &instances, challenger).expect("prove_multi failed");
        // ms → ns/iter (one iter == one full prove)
        samples.push((perf.now() - t0) * 1_000_000.0);
    }
    samples
}
