//! WASM benchmarks for the public hash primitives.
//!
//! Each `bench_*` function is exported via `wasm-bindgen` and invoked by the
//! Playwright driver from JS. The function:
//!   1. Constructs the bench's input data (deterministic seeded RNG).
//!   2. Runs `warmup_iterations` un-timed iterations to settle the V8 JIT.
//!   3. Runs `num_batches` batches of `batch_size` iterations each, timed via
//!      `performance.now()` per batch (post-Spectre, single-iter timing is
//!      too coarse — batching amortizes timer noise).
//!   4. Returns a `Vec<f64>` of per-iteration times in nanoseconds, one entry
//!      per batch.
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
        poseidon2::Poseidon2,
        rpo::Rpo256,
        rpx::Rpx256,
    },
};
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
    let perf = web_sys::window()
        .expect("no window")
        .performance()
        .expect("no performance");

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
