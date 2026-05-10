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

// Per-bench tuning: pick batch_size so each batch is ~5–10 ms (well above
// performance.now()'s ~5 µs precision in cross-origin-isolated contexts —
// or even ~100 µs in non-isolated, which is what we run in). num_batches
// is fixed at 30 so the median + IQR are stable. warmup is one batch
// worth, untimed, to settle V8's JIT.
//
// Per-op cost ranges (rough, updated as we land baseline data):
//   Blake3 merge:    ~100 ns/op  → batch_size 100_000
//   Keccak merge:    ~700 ns/op  → batch_size 15_000
//   Poseidon2 merge: ~5 µs/op    → batch_size 2_000
//   Rpo/Rpx merge:   ~5 µs/op    → batch_size 2_000
//   100-felt seq:    ~10 µs/op   → batch_size 1_000
const BENCH_CONFIG = {
  bench_blake3_256_merge:                  { num_batches: 30, batch_size: 100_000, warmup: 100_000 },
  bench_blake3_256_sequential_felt_100:    { num_batches: 30, batch_size: 5_000,   warmup: 5_000 },
  bench_keccak256_merge:                   { num_batches: 30, batch_size: 15_000,  warmup: 15_000 },
  bench_keccak256_sequential_felt_100:     { num_batches: 30, batch_size: 5_000,   warmup: 5_000 },
  bench_poseidon2_merge:                   { num_batches: 30, batch_size: 2_000,   warmup: 2_000 },
  bench_poseidon2_sequential_felt_100:     { num_batches: 30, batch_size: 200,     warmup: 200 },
  bench_rpo256_merge:                      { num_batches: 30, batch_size: 2_000,   warmup: 2_000 },
  bench_rpo256_sequential_felt_100:        { num_batches: 30, batch_size: 200,     warmup: 200 },
  bench_rpx256_merge:                      { num_batches: 30, batch_size: 2_000,   warmup: 2_000 },
  bench_rpx256_sequential_felt_100:        { num_batches: 30, batch_size: 200,     warmup: 200 },
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
      ({ name, cfg }) =>
        Array.from(window.__bench__[name](cfg.num_batches, cfg.batch_size, cfg.warmup)),
      { name, cfg },
    );

    const med = median(samples);
    process.stderr.write(`${name}: median=${med.toFixed(1)} ns/iter (n=${samples.length})\n`);

    // Format expected by benchmark-action/github-action-benchmark when
    // `tool: customSmallerIsBetter`. Each entry is one tracked metric.
    // We surface the median; sample distribution is preserved for
    // post-hoc analysis via the workflow artifact (see bench.yml).
    results.push({
      name: name.replace(/^bench_/, ""),
      unit: "ns/iter",
      value: med,
      // `extra` is shown verbatim in the chart tooltip — useful when
      // diagnosing variance later.
      extra: `n=${samples.length} batch_size=${cfg.batch_size} warmup=${cfg.warmup}`,
    });
  }

  await browser.close();
  serve.kill();

  process.stdout.write(JSON.stringify(results, null, 2) + "\n");
}

main().catch((err) => {
  process.stderr.write(`driver failed: ${err.stack || err.message}\n`);
  process.exit(1);
});
