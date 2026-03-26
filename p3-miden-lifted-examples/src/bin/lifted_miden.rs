//! Lifted STARK benchmark with a dummy Miden-shaped AIR on Goldilocks + Poseidon2.
//!
//! Two traces: 51 columns at 2^18 and 20 columns at 2^19, degree-9 constraint
//! (8 quotient chunks), 8 EF aux columns. Exercises the multi-height architecture
//! with heterogeneous widths.
//!
//! ```bash
//! BENCH_ITERS=3 RUST_LOG=debug RUSTFLAGS="-C target-cpu=native" \
//!   cargo run -p p3-miden-lifted-examples --release --features parallel --bin lifted_miden
//! ```

use p3_matrix::Matrix;
use p3_miden_lifted_air::{AirInstance, AirWitness, LiftedAir};
use p3_miden_lifted_examples::{
    bench_configs::{self, Challenge, Val},
    miden::{
        DummyMidenAir, DummyMidenAuxBuilder, NUM_AUX_COLS, TRACE1_LOG_HEIGHT, TRACE1_WIDTH,
        TRACE2_LOG_HEIGHT, TRACE2_WIDTH, generate_dummy_trace,
    },
    stats,
    stats::{bench_iters, init_tracing},
};
use p3_miden_lifted_stark::prover::prove_multi;
use p3_miden_lmcs::testing::goldilocks_poseidon2 as gl;
use tracing::info_span;

const LOG_BLOWUP: u8 = 3;
const NUM_QUERIES: usize = 100;
const POW_BITS: usize = 16;

fn main() {
    let stats_handle = init_tracing();
    let bench_iters = bench_iters();

    let config = bench_configs::lifted_config(LOG_BLOWUP, NUM_QUERIES, POW_BITS);

    // --- Generate traces ---
    let air1 = DummyMidenAir::new(TRACE1_WIDTH, NUM_AUX_COLS);
    let air2 = DummyMidenAir::new(TRACE2_WIDTH, NUM_AUX_COLS);

    let trace1 = info_span!(
        "generate trace 1",
        width = TRACE1_WIDTH,
        log_height = TRACE1_LOG_HEIGHT
    )
    .in_scope(|| generate_dummy_trace::<Val>(TRACE1_WIDTH, TRACE1_LOG_HEIGHT));

    let trace2 = info_span!(
        "generate trace 2",
        width = TRACE2_WIDTH,
        log_height = TRACE2_LOG_HEIGHT
    )
    .in_scope(|| generate_dummy_trace::<Val>(TRACE2_WIDTH, TRACE2_LOG_HEIGHT));

    tracing::info!(
        trace1_height = trace1.height(),
        trace1_width = trace1.width(),
        trace2_height = trace2.height(),
        trace2_width = trace2.width(),
        log_quotient_degree =
            <DummyMidenAir as LiftedAir<Val, Challenge>>::log_quotient_degree(&air1),
        "trace dims"
    );

    let log1 = TRACE1_LOG_HEIGHT;
    let log2 = TRACE2_LOG_HEIGHT;

    for i in 0..=bench_iters {
        if i == 0 {
            tracing::info!("warm-up iteration");
        } else {
            tracing::info!(iteration = i, total = bench_iters, "bench iteration");
        }

        // Ascending height order: trace1 (2^18) < trace2 (2^19).
        let aux1 = DummyMidenAuxBuilder {
            num_aux_cols: NUM_AUX_COLS,
        };
        let aux2 = DummyMidenAuxBuilder {
            num_aux_cols: NUM_AUX_COLS,
        };
        let instances: Vec<(&DummyMidenAir, AirWitness<'_, Val>, &DummyMidenAuxBuilder)> = vec![
            (&air1, AirWitness::new(&trace1, &[], &[]), &aux1),
            (&air2, AirWitness::new(&trace2, &[], &[]), &aux2),
        ];

        let output = info_span!("prove").in_scope(|| {
            prove_multi(&config, &instances, gl::test_challenger()).expect("proving failed")
        });

        if i == 1 {
            let size = stats::serialized_size(&output.proof);
            println!(
                "proof size: {} ({} field elems, {} commitments)",
                stats::format_bytes(size),
                output.proof.fields().len(),
                output.proof.commitments().len(),
            );
        }

        info_span!("verify").in_scope(|| {
            let verifier_instances: Vec<(&DummyMidenAir, AirInstance<'_, Val>)> = vec![
                (
                    &air1,
                    AirInstance {
                        log_trace_height: log1,
                        public_values: &[],
                        var_len_public_inputs: &[],
                    },
                ),
                (
                    &air2,
                    AirInstance {
                        log_trace_height: log2,
                        public_values: &[],
                        var_len_public_inputs: &[],
                    },
                ),
            ];
            let digest = p3_miden_lifted_stark::verifier::verify_multi(
                &config,
                &verifier_instances,
                &output.proof,
                gl::test_challenger(),
            )
            .expect("verification failed");
            assert_eq!(output.digest, digest);
        });

        if i == 0 {
            stats_handle.clear();
        }
    }

    stats_handle.print_summary();
}
