#![cfg(test)]
//! This module contains utility functions for testing the large forest.

use alloc::{string::ToString, vec::Vec};
use core::error::Error;

use miden_field::{Felt, Word};
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Map, ONE, ZERO,
    merkle::smt::{
        ForestOperation, LeafIndex, LineageId, MAX_LEAF_ENTRIES, SMT_DEPTH, SmtUpdateBatch,
        VersionId,
    },
};

// CONSTANTS
// ================================================================================================

/// The minimum number of entries that can be included in a batch.
const MIN_BATCH_ENTRIES: usize = 0;

/// The maximum number of entries that can be included in a batch.
const MAX_BATCH_ENTRIES: usize = 300;

// UTILS
// ================================================================================================

/// Converts the provided `error` into a test case failure.
///
/// This is necessary because the `From<impl Error>` implementation is only available in builds with
/// `std` enabled, and we want error forwarding to not suck.
pub fn to_fail(error: impl Error) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

// PROPERTY TEST GENERATORS
// ================================================================================================

/// Generates an arbitrary lineage id.
pub fn arbitrary_lineage() -> impl Strategy<Value = LineageId> {
    prop::array::uniform32(any::<u8>()).prop_map(LineageId::new)
}

/// Generates an arbitrary version identifier.
pub fn arbitrary_version() -> impl Strategy<Value = VersionId> {
    // As the proptests occasionally increment the version they are given, we exclude u64::MAX just
    // in case. The probability is vanishingly unlikely though.
    0..u64::MAX
}

/// Generates an arbitrary valid felt value.
pub fn arbitrary_felt() -> impl Strategy<Value = Felt> {
    prop_oneof![any::<u64>().prop_map(Felt::new), Just(ZERO), Just(ONE)]
}

/// Generates an arbitrary valid word value.
pub fn arbitrary_word() -> impl Strategy<Value = Word> {
    prop_oneof![prop::array::uniform4(arbitrary_felt()).prop_map(Word::new), Just(Word::empty()),]
}

/// Generates a random number of unique (non-overlapping) key-value pairs.
///
/// Note that the generated pairs may well have the same leaf index.
pub fn arbitrary_entries() -> impl Strategy<Value = Vec<(Word, Word)>> {
    prop::collection::vec(
        (arbitrary_word(), arbitrary_word()),
        MIN_BATCH_ENTRIES..=MAX_BATCH_ENTRIES,
    )
    .prop_map(move |entries| {
        // We want to avoid duplicate entries. It is well-defined, but it helps with test simplicity
        // to avoid it here.
        let mut keys_in_leaf: Map<LeafIndex<SMT_DEPTH>, usize> = Map::default();

        entries
            .into_iter()
            .flat_map(|(k, v)| {
                let leaf_index = LeafIndex::from(k);
                let count = keys_in_leaf.entry(leaf_index).or_default();

                // We don't want to overfill a leaf.
                if *count >= MAX_LEAF_ENTRIES {
                    return None;
                } else {
                    *count += 1;
                }

                Some((k, v))
            })
            .collect()
    })
}

/// Generates an arbitrary batch of updates to be performed on an arbitrary tree.
pub fn arbitrary_batch() -> impl Strategy<Value = SmtUpdateBatch> {
    arbitrary_entries().prop_map(|e| {
        SmtUpdateBatch::new(e.into_iter().map(|(k, v)| {
            if v == EMPTY_WORD {
                ForestOperation::remove(k)
            } else {
                ForestOperation::insert(k, v)
            }
        }))
    })
}
