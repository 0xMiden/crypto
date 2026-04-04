//! Lifted STARK prover and verifier (LMCS-based).
//!
//! This crate is the main facade for the lifted STARK protocol. It re-exports types from
//! sub-crates under namespaced modules so consumers can depend on just this crate.
//!
//! # Modules
//!
//! - [`proof`]: [`proof::StarkProof`], [`proof::StarkDigest`], [`proof::StarkOutput`], [`proof::StarkTranscript`]
//! - [`air`]: AIR traits, instance/witness types, and upstream `p3-air` re-exports
//! - [`prover`]: [`prover::prove_single`] / [`prover::prove_multi`] entry points
//! - [`verifier`]: [`verifier::verify_single`] / [`verifier::verify_multi`] entry points
//! - [`fri`]: PCS parameters, transcript types, and error types (DEEP + FRI)
//! - [`lmcs`]: LMCS configuration, proof types, and MMCS compatibility
//! - [`transcript`]: Fiat-Shamir channels and transcript data
//! - [`hasher`]: Stateful hasher primitives for LMCS construction
//!
//! # AIR Trust Model
//!
//! The lifted STARK has three trust domains:
//!
//! 1. **AIR = trusted** — [`air::LiftedAir`] implementations are
//!    correct application code. It is the AIR implementer's responsibility to satisfy the
//!    contract below. [`air::LiftedAir::validate`]
//!    checks the statically-verifiable subset.
//!
//! 2. **Instance = validated** — The prover validates that its witness matches the AIR spec.
//!    The verifier validates instance metadata.
//!    Both return structured errors.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors,
//!    constraint mismatch, etc.).
//!
//! ## Validated properties
//!
//! These are checked by [`air::LiftedAir::validate`]
//! and [`air::AirInstance::validate`], and enforced
//! by both prover and verifier before proceeding:
//!
//! - **No preprocessed trace** — the lifted protocol does not support them.
//! - **Positive aux width** — every AIR must have an auxiliary trace.
//! - **Periodic columns** — each has positive, power-of-two length ≤ trace height.
//! - **Constraint degree** — `log_quotient_degree() ≤ log_blowup`.
//! - **Instance dimensions** — trace width, public values length, var-len public
//!   inputs count, and trace height (power of two) all match the AIR specification.
//!
//! ## Unchecked trust assumptions
//!
//! These cannot be verified statically and are the AIR implementer's responsibility:
//!
//! 1. **Window size** — Only transition window size 2.
//! 2. **Deterministic constraints** — `eval()` emits the same number and types of
//!    constraints regardless of builder implementation.
//! 3. **Consistent aux builder** — `AuxBuilder::build_aux_trace` returns
//!    width = `aux_width()`, height = main trace height, and exactly
//!    `num_aux_values()` values. (The prover asserts these at runtime as a
//!    defense-in-depth sanity check.)
//! 4. **Sound `reduced_aux_values`** — Returns correct bus contributions for valid inputs.

#![no_std]

extern crate alloc;

mod config;
/// Domain/coset operations for lifted traces.
pub mod coset;
/// Debug constraint checker for lifted AIRs.
pub mod debug;
pub(crate) mod selectors;

pub use config::*;

pub mod proof;
pub mod prover;
pub mod verifier;

// ============================================================================
// Namespaced re-exports from sub-crates
// ============================================================================

/// AIR traits, instance/witness types, and upstream `p3-air` re-exports.
///
/// This module re-exports items from [`p3_miden_lifted_air`], which in turn
/// re-exports `p3-air` types. Consumers should never need to depend on `p3-air`
/// directly.
pub mod air {
    pub use p3_miden_lifted_air::{
        // Upstream p3-air re-exports
        Air,
        AirBuilder,
        AirBuilderWithContext,
        // Lifted AIR types
        AirInstance,
        AirValidationError,
        AirWitness,
        AuxBuilder,
        BaseAir,
        EmptyWindow,
        ExtensionBuilder,
        FilteredAirBuilder,
        LiftedAir,
        LiftedAirBuilder,
        PeriodicAirBuilder,
        PermutationAirBuilder,
        ReducedAuxValues,
        ReductionError,
        RowWindow,
        TracePart,
        VarLenPublicInputs,
        WindowAccess,
        log2_strict_u8,
        validate_instances,
    };

    /// Symbolic constraint analysis types from upstream p3-air.
    pub mod symbolic {
        pub use p3_miden_lifted_air::symbolic::*;
    }

    /// Auxiliary trace types (builder, cross-AIR identity checking).
    pub mod auxiliary {
        pub use p3_miden_lifted_air::auxiliary::*;
    }

    /// AIR constraint utility functions from upstream p3-air.
    pub mod utils {
        pub use p3_miden_lifted_air::utils::*;
    }
}

/// PCS parameter types, transcript views, and error types for DEEP + FRI.
pub mod fri {
    pub use p3_miden_lifted_fri::{
        OpenedValues, PcsError, PcsParams, PcsParamsError, PcsTranscript,
        deep::{DeepError, DeepTranscript},
        fri::{FriError, FriRoundTranscript, FriTranscript},
    };
}

/// LMCS configuration, tree types, and proof structures.
pub mod lmcs {
    pub use p3_miden_lmcs::{
        HidingLmcsConfig, LiftedMerkleTree, Lmcs, LmcsConfig, LmcsError, LmcsTree, OpenedRows,
        RowList,
        proof::{LeafOpening, Proof},
    };
}

/// Fiat-Shamir transcript channels and data types.
pub mod transcript {
    pub use p3_miden_transcript::{TranscriptChallenger, TranscriptData, TranscriptError};
}

/// Stateful hasher primitives for LMCS construction.
pub mod hasher {
    pub use p3_miden_stateful_hasher::{
        Alignable, ChainingHasher, SerializingStatefulSponge, StatefulHasher, StatefulSponge,
    };
}
