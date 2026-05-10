# miden-bench-wasm

WASM benchmarks for the public hash primitives in `miden-crypto`, run in
headless Chromium so the numbers reflect what the wallet's actual users
experience (V8 JIT codegen, browser memory model) rather than what a
non-browser runtime like `wasmtime` would produce.

## What's tracked

Three layers, each catches a different class of regression:

### 1. Hash-primitive throughput (`merge` + `hash_elements(100 felts)`)

| Algorithm   | merge bench                          | sequential bench                                |
| ----------- | ------------------------------------ | ----------------------------------------------- |
| RPO256      | `bench_rpo256_merge`                 | `bench_rpo256_sequential_felt_100`              |
| RPX256      | `bench_rpx256_merge`                 | `bench_rpx256_sequential_felt_100`              |
| Poseidon2   | `bench_poseidon2_merge`              | `bench_poseidon2_sequential_felt_100`           |
| Blake3_256  | `bench_blake3_256_merge`             | `bench_blake3_256_sequential_felt_100`          |
| Keccak256   | `bench_keccak256_merge`              | `bench_keccak256_sequential_felt_100`           |

Catches general regressions in the public hash API. Goes through the
**scalar** (WIDTH=1) fast path of the trait-generic Permutation impl —
identical numbers between `next` and the simd128 PR, by design (the
const-folded WIDTH=1 path is meant to be a zero-cost no-op).

### 2. Packed-permutation throughput

| Algorithm | bench                                 |
| --------- | ------------------------------------- |
| RPO256    | `bench_rpo256_packed_permute`         |
| RPX256    | `bench_rpx256_packed_permute`         |
| Poseidon2 | `bench_poseidon2_packed_permute`      |

Runs `permute_mut(&mut [<Felt as Field>::Packing; 12])`. Resolves to:
- **`Felt`** on `next` → WIDTH=1 → scalar perm (matches layer 1's
  numbers; co-tracked as a sanity check on the const-folded fast path).
- **`PackedFelt`** on the simd128 PR (#998) → WIDTH=2 → packed perm,
  ns/iter halves.

This is the layer that **automatically shows the simd128 win** the
moment #998 lands, with no bench-source changes required.

### 3. End-to-end synthetic prove

| bench                                 | shape                                       |
| ------------------------------------- | ------------------------------------------- |
| `bench_lifted_stark_prove_blake3`     | full prove of a 4096-row Blake3 AIR trace  |

Drives `miden-lifted-stark::prove_multi` through the complete pipeline
(LDE → constraint folding → DEEP composition → FRI → LMCS Merkle).
Same arithmetic shape a real prove hits, on a synthetic AIR small
enough to fit a 15-minute CI budget. PCS params are calibrated for
fast bench runs (log_blowup=1, no PoW) — this is a perf-tracking bench,
not a security parameter; only the relative number matters.

The simd128 PR's gain on packed ext-field math should drop this number
~30-50% — that's the headline regression-tracking signal for "did this
PR slow down the prove stack?"

### Storage + alerts

The driver reports the median across samples as each bench's tracked
metric; `benchmark-action/github-action-benchmark` stores each median
over time on the `gh-pages` branch (under `bench/wasm/`, separate from
`docs/`) and posts a sticky PR comment with the diff vs the latest
`next` baseline. Alerts fire on regression > 15 %.

## Running locally

Prereqs: Rust 1.90+, `wasm-pack`, Node 18+, Chromium auto-installed by
Playwright.

```bash
# 1. Build the WASM lib + JS bindings into static/pkg/
wasm-pack build --release --target web --out-dir static/pkg miden-bench-wasm

# 2. Install JS deps (Playwright + serve)
cd miden-bench-wasm && npm install

# 3. Run the bench (writes JSON to stdout, status to stderr)
npx playwright install chromium  # first run only
node driver.mjs > /tmp/results.json
```

The output is:

```json
[
  { "name": "rpo256_merge", "unit": "ns/iter", "value": 4831.2, "extra": "n=30 batch_size=2000 warmup=2000" },
  …
]
```

## Tuning a bench

Per-bench `num_batches` / `batch_size` / `warmup` are in `driver.mjs`'s
`BENCH_CONFIG`. Goals:

- `batch_size` × per-op cost ≈ **5–10 ms** per batch. Below 5 ms, timer
  noise dominates. Above 10 ms, you're just paying for run length without
  improving variance.
- `num_batches = 30` gives a stable median + IQR. More is over-spend; less
  exposes unrelated infra noise on shared GHA runners.
- `warmup ≈ batch_size` gives V8 one full batch of un-timed iterations to
  settle JIT tier-up before the timed batches begin.

If a new bench's variance is high in CI, double `batch_size` first
(more amortization), then double `num_batches` (more samples for the
median). The 15 % alert threshold in `bench.yml` is calibrated against
this tuning — it'll need re-tuning if the runs get noisier.

## Why headless Chromium and not wasmtime

The wallet (and any browser-based dApp consumer) runs in V8. V8 and
Cranelift (`wasmtime`'s codegen backend) produce meaningfully different
machine code from the same `wasm32+simd128` input — SIMD codegen quality
can differ 1.5–2 ×. A `wasmtime` benchmark could cleanly miss a real
regression that only shows up in V8. For perf signals we'd actually act
on, we want to be measuring what users see.

The cost of headless Chromium (~3 s for spinup vs `wasmtime`'s ~50 ms)
is paid once per workflow run, not per bench, so the marginal cost is
negligible.

## Why no COOP/COEP

The benches in scope are single-threaded pure compute. No
`SharedArrayBuffer`, no `Workers`, no rayon, no `wasm-bindgen-rayon`.
Skipping COOP/COEP cuts ~3 s from CI and removes the SW-reload flake
that the wallet's prove harness routinely hits. If a future bench needs
SAB (e.g. parallel SMT construction), we'll add COOP/COEP at that
point — the rest of the harness is unchanged.

## Why this lives in `miden-bench-wasm/` and not `miden-crypto/benches-wasm/`

Workspace member > sibling-of-benches. Reasons:

- The native `cargo bench` machinery doesn't run on `wasm32-unknown-unknown`
  (no `std::time::Instant`, no `std::thread`); we'd be putting our wasm
  bench code right next to native benches that look identical at the
  `cargo bench` invocation level but in fact require completely different
  invocation tooling. Confusing.
- Workspace members have their own `Cargo.toml`, dep set, and
  `crate-type = ["cdylib", "rlib"]` — a clean fit for a wasm-bindgen
  target.
- `miden-bench` already exists for STARK profiling at the workspace level;
  this is the symmetric setup for the wasm side.
