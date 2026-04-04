#![allow(dead_code)]

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_miden_lifted_stark::{
    GenericStarkConfig,
    air::{AirWitness, AuxBuilder, LiftedAir},
    fri::PcsParams,
    proof::StarkTranscript,
};
use p3_miden_lmcs::testing::goldilocks_poseidon2::{
    Challenger, EF, F, Lmcs, test_challenger, test_lmcs,
};

pub type TestConfig = GenericStarkConfig<F, EF, Lmcs, p3_dft::Radix2DitParallel<F>, Challenger>;

/// Generate a power-of-4 chain trace: `[start, start⁴, start¹⁶, start⁶⁴, ...]`
pub fn generate_pow4_trace(start: F, height: usize) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(height);
    let mut current = start;
    for _ in 0..height {
        values.push(current);
        current = current.exp_power_of_2(2);
    }
    RowMajorMatrix::new(values, 1)
}

pub fn test_config() -> TestConfig {
    let pcs = PcsParams::new(
        2, // log_blowup
        1, // log_folding_arity
        2, // log_final_degree
        0, // folding_pow_bits
        0, // deep_pow_bits
        2, // num_queries
        0, // query_pow_bits
    )
    .unwrap();

    let lmcs = test_lmcs();
    let dft = p3_dft::Radix2DitParallel::<F>::default();

    GenericStarkConfig::new(pcs, lmcs, dft, test_challenger())
}

/// Prove and verify from pre-built prover instances.
///
/// Runs the full prove → verify → transcript-reparse cycle.
pub fn prove_and_verify_instances<A, B>(instances: &[(&A, AirWitness<'_, F>, &B)])
where
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    let config = test_config();

    let output = p3_miden_lifted_stark::prover::prove_multi(&config, instances, test_challenger())
        .expect("proving should succeed");

    let verifier_instances: Vec<_> = instances
        .iter()
        .map(|(a, w, _)| (*a, w.to_instance().unwrap()))
        .collect();

    let verifier_digest = p3_miden_lifted_stark::verifier::verify_multi(
        &config,
        &verifier_instances,
        &output.proof,
        test_challenger(),
    )
    .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);

    // Re-parse transcript from a fresh challenger and verify digest agreement.
    let (_, reparse_digest) = StarkTranscript::from_proof(
        &config,
        &verifier_instances,
        &output.proof,
        test_challenger(),
    )
    .expect("transcript re-parse should succeed");
    assert_eq!(output.digest, reparse_digest);
}

/// Prove and verify multiple traces, each with its own public values.
///
/// `instances` is a slice of `(trace, public_values)` pairs in ascending height order.
pub fn prove_and_verify<A, B>(air: &A, aux_builder: &B, instances: &[(RowMajorMatrix<F>, Vec<F>)])
where
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    let prover_instances: Vec<_> = instances
        .iter()
        .map(|(t, pv)| (air, AirWitness::new(t, pv, &[]), aux_builder))
        .collect();

    prove_and_verify_instances(&prover_instances);
}
