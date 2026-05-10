// Headless Chromium driver for the miden-crypto WASM bench harness.
//
// Usage: node driver.mjs > results.json
//
// The script:
//   1. Spins up `npx serve` to host static/ (with pkg/ from wasm-pack).
//   2. Launches headless Chromium via Playwright.
//   3. Loads bench.html, waits for window.__bench__ to populate.
//   4. For each bench function, calls it via page.evaluate with tuned
//      (num_batches, batch_size, warmup) params, collects the per-batch
//      ns/iter samples, computes summary stats.
//   5. Writes a JSON array to stdout in the format the
//      benchmark-action/github-action-benchmark action expects for
//      `tool: customSmallerIsBetter`.
//
// Why headless Chromium and not wasmtime: the wallet's actual users run
// in V8 (Chrome/Brave/Edge), and SIMD codegen / JIT behavior differs
// meaningfully between engines. A wasmtime number wouldn't reflect what
// users see. See the PR description for the engine-fidelity argument.
//
// Why no COOP/COEP: these benches are single-threaded pure compute. No
// SharedArrayBuffer, no Workers, no rayon. Skipping COOP/COEP cuts ~3 s
// of CI time and removes the SW-reload flake the wallet's prove harness
// hits.

import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const STATIC_DIR = resolve(__dirname, "static");
const PORT = 3022;

// Per-bench tuning. Two shapes:
//
//   "batched"  → (num_batches, batch_size, warmup): the function runs
//                num_batches batches of batch_size iterations each, with
//                `warmup` un-timed iterations preceding. Returns one
//                ns/iter sample per batch.
//
//   "runs"     → (num_runs, log_n): the function runs num_runs full
//                proves of a 2^log_n-row trace. Returns one ns/run
//                sample per run.
//
// Tuning targets — calibrated for a 10 % regression threshold (see
// bench.yml). Two knobs drive variance down:
//
//   - batch_size × per-op cost ≥ 20 ms per batch. At 20 ms,
//     `performance.now()`'s ~100 µs unisolated precision contributes
//     ~0.5 % timer noise per batch — well under the 10 % alert
//     threshold. (Going bigger doesn't help; the median is robust
//     enough that 50 batches × 20 ms hits diminishing returns.)
//
//   - num_batches = 50. Stable median + tight IQR; 30 was leaving
//     occasional outliers on shared GHA runners. The 50 → median trim
//     gets us below 5 % run-to-run variance in informal local testing
//     (Apple M5 + nominal CPU contention).
//
// If a metric still triggers spurious 10 % alerts in production, the
// next move is per-bench tuning (more batches first, then bigger
// batch sizes), then `iai-callgrind` for native instruction-count
// measurement, NOT a wider alert threshold.
const BENCH_CONFIG = {
  // Public-API hash-primitive throughput (scalar fast-path; same numbers
  // on `next` and on the simd128 PR — these track general regressions,
  // NOT the simd128 win specifically).
  //   Blake3 merge:   ~60 ns/op  → batch 400_000 (≈24 ms/batch)
  //   Keccak merge:   ~160 ns/op → batch 150_000 (≈24 ms/batch)
  //   Algebraic merge:~5 µs/op   → batch 5_000   (≈25 ms/batch)
  //   Felt-100 seq:   ~25 µs/op  → batch 1_000   (≈25 ms/batch)
  bench_blake3_256_merge:                  { shape: "batched", num_batches: 50, batch_size: 400_000, warmup: 100_000 },
  bench_blake3_256_sequential_felt_100:    { shape: "batched", num_batches: 50, batch_size: 30_000,  warmup: 5_000 },
  bench_keccak256_merge:                   { shape: "batched", num_batches: 50, batch_size: 150_000, warmup: 15_000 },
  bench_keccak256_sequential_felt_100:     { shape: "batched", num_batches: 50, batch_size: 25_000,  warmup: 5_000 },
  bench_poseidon2_merge:                   { shape: "batched", num_batches: 50, batch_size: 15_000,  warmup: 2_000 },
  bench_poseidon2_sequential_felt_100:     { shape: "batched", num_batches: 50, batch_size: 1_500,   warmup: 200 },
  bench_rpo256_merge:                      { shape: "batched", num_batches: 50, batch_size: 5_000,   warmup: 2_000 },
  bench_rpo256_sequential_felt_100:        { shape: "batched", num_batches: 50, batch_size: 500,     warmup: 200 },
  bench_rpx256_merge:                      { shape: "batched", num_batches: 50, batch_size: 5_000,   warmup: 2_000 },
  bench_rpx256_sequential_felt_100:        { shape: "batched", num_batches: 50, batch_size: 1_000,   warmup: 200 },
  // Packed-permutation throughput. On `next` these go through the
  // WIDTH=1 const-folded fast path (= scalar perm). After PR #998 lands,
  // the same call resolves to WIDTH=2 packed perm and ns/iter halves.
  // The dashboard step-down on this metric *is* the simd128 win.
  bench_rpo256_packed_permute:             { shape: "batched", num_batches: 50, batch_size: 5_000,   warmup: 2_000 },
  bench_rpx256_packed_permute:             { shape: "batched", num_batches: 50, batch_size: 5_000,   warmup: 2_000 },
  bench_poseidon2_packed_permute:          { shape: "batched", num_batches: 50, batch_size: 15_000,  warmup: 2_000 },
  // End-to-end synthetic prove. log_n=10 (1024-row Blake3 AIR trace,
  // ~1 s per prove) + n=15 runs gives a tighter median than log_n=12 +
  // n=5 in similar wall clock — more samples, smaller per-sample noise
  // proportion. The trace is still big enough that LDE / FRI / Merkle /
  // constraint folding all run, just shorter.
  bench_lifted_stark_prove_blake3:         { shape: "runs",    num_runs: 15,    log_n: 10 },
};

function median(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function main() {
  // Static-file server. `npx serve` from local node_modules — installed
  // by the workflow's `npm install` step.
  const serve = spawn("npx", ["serve", STATIC_DIR, "-l", String(PORT), "-L"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Drain serve's stdout to keep the pipe healthy.
  serve.stdout?.on("data", () => {});
  serve.stderr?.on("data", () => {});

  // Wait for serve to bind.
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://localhost:${PORT}/bench.html`);
      if (r.ok) break;
    } catch {}
    await sleep(100);
  }

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on("pageerror", (err) => process.stderr.write(`[pageerror] ${err.message}\n`));
  page.on("console", (msg) => {
    if (msg.type() === "error") process.stderr.write(`[browser-error] ${msg.text()}\n`);
  });

  await page.goto(`http://localhost:${PORT}/bench.html`, { waitUntil: "load" });
  await page.waitForFunction(() => window.__bench__ && Object.keys(window.__bench__).length > 0, null, {
    timeout: 30_000,
  });

  const results = [];
  for (const [name, cfg] of Object.entries(BENCH_CONFIG)) {
    const samples = await page.evaluate(
      ({ name, cfg }) => {
        const fn = window.__bench__[name];
        if (cfg.shape === "batched") {
          return Array.from(fn(cfg.num_batches, cfg.batch_size, cfg.warmup));
        } else if (cfg.shape === "runs") {
          return Array.from(fn(cfg.num_runs, cfg.log_n));
        }
        throw new Error(`unknown shape: ${cfg.shape}`);
      },
      { name, cfg },
    );

    const med = median(samples);
    process.stderr.write(`${name}: median=${med.toFixed(1)} ns/iter (n=${samples.length})\n`);

    // Format expected by benchmark-action/github-action-benchmark when
    // `tool: customSmallerIsBetter`. Each entry is one tracked metric.
    // We surface the median; sample distribution is preserved for
    // post-hoc analysis via the workflow artifact (see bench.yml).
    const extra = cfg.shape === "batched"
      ? `n=${samples.length} batch_size=${cfg.batch_size} warmup=${cfg.warmup}`
      : `n=${samples.length} log_n=${cfg.log_n}`;
    results.push({
      name: name.replace(/^bench_/, ""),
      unit: "ns/iter",
      value: med,
      // `extra` is shown verbatim in the chart tooltip — useful when
      // diagnosing variance later.
      extra,
    });
  }

  await browser.close();
  serve.kill();

  process.stdout.write(JSON.stringify(results, null, 2) + "\n");
}

// Explicit `process.exit(0)` after main() returns. Without this, Node's
// event loop stays alive (open file descriptors from the `npx serve`
// child's piped stdio + Playwright's lingering handles), and the driver
// hangs until GHA's job timeout fires — even though every bench has
// completed and the JSON has been written. SIGKILL on the child doesn't
// reliably clear the parent's piped fds. Just exit.
main()
  .then(() => process.exit(0))
  .catch((err) => {
    process.stderr.write(`driver failed: ${err.stack || err.message}\n`);
    process.exit(1);
  });
