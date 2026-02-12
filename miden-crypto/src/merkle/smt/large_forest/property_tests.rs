#![cfg(test)]
//! This module contains the property tests for the SMT forest.

use alloc::{collections::BTreeSet, string::ToString, vec::Vec};
use core::error::Error;

use itertools::Itertools;
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Felt, Map, ONE, Word, ZERO,
    merkle::smt::{
        ForestInMemoryBackend, ForestOperation, LargeSmtForest, LeafIndex, LineageId,
        MAX_LEAF_ENTRIES, SMT_DEPTH, Smt, SmtUpdateBatch, TreeEntry, TreeId, VersionId,
    },
};

// CONSTANTS
// ================================================================================================

/// The minimum number of entries that can be included in a batch.
const MIN_BATCH_ENTRIES: usize = 0;

/// The maximum number of entries that can be included in a batch.
const MAX_BATCH_ENTRIES: usize = 10_000;

// GENERATORS
// ================================================================================================

/// Generates an arbitrary lineage id.
fn arbitrary_lineage() -> impl Strategy<Value = LineageId> {
    prop::array::uniform32(any::<u8>()).prop_map(LineageId::new)
}

/// Generates an arbitrary version identifier.
fn arbitrary_version() -> impl Strategy<Value = VersionId> {
    any::<u64>()
}

/// Generates an arbitrary valid felt value.
fn arbitrary_felt() -> impl Strategy<Value = Felt> {
    prop_oneof![any::<u64>().prop_map(Felt::new), Just(ZERO), Just(ONE)]
}

/// Generates an arbitrary valid word value.
fn arbitrary_word() -> impl Strategy<Value = Word> {
    prop_oneof![prop::array::uniform4(arbitrary_felt()).prop_map(Word::new), Just(Word::empty()),]
}

/// Generates a random number of unique (non-overlapping) key-value pairs.
///
/// Note that the generated pairs may well have the same leaf index.
fn arbitrary_entries() -> impl Strategy<Value = Vec<(Word, Word)>> {
    prop::collection::vec(
        (arbitrary_word(), arbitrary_word()),
        MIN_BATCH_ENTRIES..=MAX_BATCH_ENTRIES,
    )
    .prop_map(move |entries| {
        // We want to avoid duplicate entries. It is well-defined, but it helps with test simplicity
        // to avoid it here.
        let mut used_keys = BTreeSet::new();
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

                used_keys.insert(k);
                Some((k, v))
            })
            .collect()
    })
}

/// Generates an arbitrary batch of updates to be performed on an arbitrary tree.
fn arbitrary_batch() -> impl Strategy<Value = SmtUpdateBatch> {
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

// ENTRIES
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// This test ensures that the `entries` iterator for the forest always returns the exact same
    /// values as the `entries` iterator over a basic SMT with the same state.
    #[test]
    fn entries_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        // We now create a forest and add the lineage to it using the first set of entries.
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        // We then create two auxiliary trees to work with, to compare our results against.
        let mut tree_v1 = Smt::new();
        let tree_v1_mutations =
            tree_v1.compute_mutations(Vec::from(entries_v1).into_iter()).map_err(to_fail)?;
        tree_v1.apply_mutations(tree_v1_mutations).map_err(to_fail)?;

        let mut tree_v2 = tree_v1.clone();
        let tree_v2_mutations =
            tree_v2.compute_mutations(Vec::from(entries_v2).into_iter()).map_err(to_fail)?;
        tree_v2.apply_mutations(tree_v2_mutations).map_err(to_fail)?;

        // Iterating over the historical version of the lineage in the forest should produce exactly
        // the same entries as iterating over V1 of our test tree.
        let old_version = TreeId::new(lineage, version);
        let forest_entries = forest.entries(old_version).map_err(to_fail)?.sorted().collect_vec();
        let tree_entries = tree_v1
            .entries()
            .map(|(k, v)| TreeEntry { key: *k, value: *v })
            .sorted()
            .collect_vec();
        assert_eq!(forest_entries, tree_entries);

        // Iterating over the newest version of the lineage in the forest should provide exactly the
        // same entries as iterating over V2 of our test tree.
        let current_version = TreeId::new(lineage, version + 1);
        let forest_entries = forest.entries(current_version).map_err(to_fail)?.sorted().collect_vec();
        let tree_entries = tree_v2
            .entries()
            .map(|(k, v)| TreeEntry { key: *k, value: *v })
            .sorted()
            .collect_vec();
        assert_eq!(forest_entries, tree_entries);
    }

    /// This test ensures that the `entries` iterator for the forest will never return entries where
    /// the value is the empty word.
    #[test]
    fn entries_never_yields_empty_values(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        // We now create a forest and add the lineage to it using the first set of entries.
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        // Iterating over the historical version of the lineage in the forest should produce exactly
        // the same entries as iterating over V1 of our test tree.
        let old_version = TreeId::new(lineage, version);
        assert!(forest.entries(old_version).map_err(to_fail)?.all(|e| e.value != EMPTY_WORD));

        // Iterating over the newest version of the lineage in the forest should provide exactly the
        // same entries as iterating over V2 of our test tree.
        let current_version = TreeId::new(lineage, version + 1);
        assert!(forest.entries(current_version).map_err(to_fail)?.all(|e| e.value != EMPTY_WORD));
    }
}

// UTILS
// ================================================================================================

/// Converts the provided `error` into a test case failure.
///
/// This is necessary because the `From<impl Error>` implementation is only available in builds with
/// `std` enabled, and we want error forwarding to not suck.
fn to_fail(error: impl Error) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}
