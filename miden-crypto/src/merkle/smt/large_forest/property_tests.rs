#![cfg(test)]
//! This module contains the property tests for the SMT forest.

use alloc::{string::ToString, vec::Vec};

use itertools::Itertools;
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Word,
    merkle::smt::{
        Backend, ForestConfig, ForestInMemoryBackend, ForestOperation, LargeSmtForest, LineageId,
        RootInfo, Smt, SmtForestUpdateBatch, SmtUpdateBatch, TreeEntry, TreeId, VersionId,
        large_forest::test_utils::{
            arbitrary_batch, arbitrary_lineage, arbitrary_version, arbitrary_word, to_fail,
        },
    },
};

// HELPERS
// ================================================================================================

/// Generates two distinct lineage identifiers.
fn arbitrary_distinct_lineages() -> impl Strategy<Value = (LineageId, LineageId)> {
    (arbitrary_lineage(), arbitrary_lineage())
        .prop_filter("lineages must be distinct", |(a, b)| a != b)
}

/// Generates a non-empty word value.
fn arbitrary_non_empty_word() -> impl Strategy<Value = Word> {
    arbitrary_word().prop_filter("word must be non-empty", |word| *word != EMPTY_WORD)
}

fn build_tree(initial: SmtUpdateBatch) -> core::result::Result<Smt, TestCaseError> {
    let mut tree = Smt::new();
    apply_batch(&mut tree, initial)?;
    Ok(tree)
}

fn apply_batch(tree: &mut Smt, batch: SmtUpdateBatch) -> core::result::Result<(), TestCaseError> {
    let mutations =
        tree.compute_mutations(Vec::<(Word, Word)>::from(batch).into_iter()).map_err(to_fail)?;
    tree.apply_mutations(mutations).map_err(to_fail)
}

fn word_to_option(value: Word) -> Option<Word> {
    if value == EMPTY_WORD {
        None
    } else {
        Some(value)
    }
}

fn sorted_tree_entries(tree: &Smt) -> Vec<TreeEntry> {
    tree.entries()
        .map(|(key, value)| TreeEntry {
            key: *key,
            value: *value,
        })
        .sorted()
        .collect_vec()
}

fn sorted_forest_entries(
    forest: &LargeSmtForest<ForestInMemoryBackend>,
    tree: TreeId,
) -> core::result::Result<Vec<TreeEntry>, TestCaseError> {
    Ok(forest.entries(tree).map_err(to_fail)?.sorted().collect_vec())
}

fn batch_keys(batch: &SmtUpdateBatch) -> Vec<Word> {
    batch.clone()
        .into_iter()
        .map(|operation| operation.key())
        .collect()
}

fn assert_tree_queries_match(
    forest: &LargeSmtForest<ForestInMemoryBackend>,
    tree_id: TreeId,
    reference: &Smt,
    sample_keys: &[Word],
    assert_openings: bool,
) -> core::result::Result<(), TestCaseError> {
    let forest_entries = sorted_forest_entries(forest, tree_id)?;
    let reference_entries = sorted_tree_entries(reference);
    let reference_entry_count = reference_entries.len();
    prop_assert_eq!(forest_entries, reference_entries);
    prop_assert_eq!(forest.entry_count(tree_id).map_err(to_fail)?, reference_entry_count);

    for key in sample_keys {
        prop_assert_eq!(
            forest.get(tree_id, *key).map_err(to_fail)?,
            word_to_option(reference.get_value(key))
        );
        if assert_openings {
            prop_assert_eq!(forest.open(tree_id, *key).map_err(to_fail)?, reference.open(key));
        }
    }

    Ok(())
}

fn assert_lineage_metadata(
    forest: &LargeSmtForest<ForestInMemoryBackend>,
    lineage: LineageId,
    versions: &[(VersionId, Word)],
) -> core::result::Result<(), TestCaseError> {
    let (latest_version, latest_root) =
        versions.last().copied().expect("lineage must be non-empty");

    prop_assert_eq!(forest.latest_version(lineage), Some(latest_version));
    prop_assert_eq!(forest.latest_root(lineage), Some(latest_root));
    prop_assert_eq!(
        forest
            .lineage_roots(lineage)
            .expect("lineage must be present")
            .collect_vec(),
        versions.iter().rev().map(|(_, root)| *root).collect_vec()
    );

    for (idx, (version, root)) in versions.iter().enumerate() {
        let tree = TreeId::new(lineage, *version);
        let expected = if idx + 1 == versions.len() {
            RootInfo::LatestVersion(*root)
        } else {
            RootInfo::HistoricalVersion(*root)
        };
        prop_assert_eq!(forest.root_info(tree), expected);
    }

    Ok(())
}

// PROPERTY TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// This test ensures that the `entries` iterator for the forest always returns the exact same
    /// values as the `entries` iterator over a basic SMT with the same state.
    #[test]
    fn entries_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let tree_info =
            forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        let tree_v1 = build_tree(entries_v1.clone())?;
        let mut tree_v2 = tree_v1.clone();
        apply_batch(&mut tree_v2, entries_v2)?;

        let old_version = TreeId::new(lineage, version);
        prop_assert_eq!(
            sorted_forest_entries(&forest, old_version)?,
            sorted_tree_entries(&tree_v1)
        );

        let current_version = TreeId::new(lineage, tree_info.version());
        prop_assert_eq!(
            sorted_forest_entries(&forest, current_version)?,
            sorted_tree_entries(&tree_v2)
        );
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
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let tree_info = forest.update_tree(lineage, version + 1, entries_v2).map_err(to_fail)?;

        let old_version = TreeId::new(lineage, version);
        prop_assert!(forest.entries(old_version).map_err(to_fail)?.all(|entry| entry.value != EMPTY_WORD));

        let current_version = TreeId::new(lineage, tree_info.version());
        prop_assert!(forest.entries(current_version).map_err(to_fail)?.all(|entry| entry.value != EMPTY_WORD));
    }

    /// This test cross-checks the core query APIs (`get`, `open`, `entries`, `entry_count`) and the
    /// associated metadata APIs against a reference SMT model across current and historical versions.
    #[test]
    fn queries_and_metadata_match_reference_model(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        let add_result =
            forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let update_result =
            forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        let tree_v1 = build_tree(entries_v1.clone())?;
        let mut tree_current = tree_v1.clone();
        apply_batch(&mut tree_current, entries_v2.clone())?;

        let mut sample_keys = batch_keys(&entries_v1);
        sample_keys.extend(batch_keys(&entries_v2));
        sample_keys.push(random_key);
        sample_keys.sort();
        sample_keys.dedup();

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &tree_v1,
            &sample_keys,
            false,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, update_result.version()),
            &tree_current,
            &sample_keys,
            true,
        )?;

        let expected_versions = if tree_current.root() == tree_v1.root() {
            vec![(version, tree_v1.root())]
        } else {
            vec![(version, add_result.root()), (version + 1, tree_current.root())]
        };

        assert_lineage_metadata(&forest, lineage, &expected_versions)?;
        prop_assert_eq!(forest.lineage_count(), 1);
        prop_assert_eq!(forest.tree_count(), expected_versions.len());
        prop_assert_eq!(
            forest.roots().map(|root| (root.lineage(), root.value())).sorted().collect_vec(),
            expected_versions.iter().map(|(_, root)| (lineage, *root)).sorted().collect_vec()
        );

        let unknown_lineage = LineageId::new([0xAA; 32]);
        prop_assume!(unknown_lineage != lineage);
        prop_assert_eq!(forest.latest_version(unknown_lineage), None);
        prop_assert_eq!(forest.latest_root(unknown_lineage), None);
        prop_assert!(forest.lineage_roots(unknown_lineage).is_none());
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 2)), RootInfo::Missing);
        prop_assert_eq!(forest.root_info(TreeId::new(unknown_lineage, version)), RootInfo::Missing);
    }

    /// This test validates single-lineage mutation semantics, including duplicate additions, bad
    /// version updates, and no-op updates preserving the observable forest state.
    #[test]
    fn add_lineage_and_update_tree_preserve_state_on_failures(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        initial_entries in arbitrary_batch(),
        extra_entries in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, initial_entries.clone()).map_err(to_fail)?;
        let reference = build_tree(initial_entries.clone())?;

        let mut sample_keys = batch_keys(&initial_entries);
        sample_keys.extend(batch_keys(&extra_entries));
        sample_keys.push(random_key);
        sample_keys.sort();
        sample_keys.dedup();

        let duplicate = forest.add_lineage(lineage, version + 1, extra_entries.clone());
        prop_assert!(duplicate.is_err());
        prop_assert_eq!(
            duplicate.unwrap_err().to_string(),
            format!("Duplicate lineage ID {lineage} provided")
        );
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &reference,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.lineage_count(), 1);
        prop_assert_eq!(forest.tree_count(), 1);

        let bad_version = forest.update_tree(lineage, version, extra_entries);
        prop_assert!(bad_version.is_err());
        prop_assert_eq!(
            bad_version.unwrap_err().to_string(),
            format!("Version {version} is not newer than latest-known {version}")
        );
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &reference,
            &sample_keys,
            true,
        )?;

        let no_op = forest
            .update_tree(lineage, version + 1, SmtUpdateBatch::empty())
            .map_err(to_fail)?;
        prop_assert_eq!(no_op.version(), version);
        prop_assert_eq!(no_op.root(), reference.root());
        prop_assert_eq!(forest.latest_version(lineage), Some(version));
        prop_assert_eq!(forest.tree_count(), 1);
    }

    /// This test validates batch updates across multiple lineages and ensures invalid batches do
    /// not partially modify forest state.
    #[test]
    fn update_forest_matches_reference_model_and_preserves_state_on_error(
        (lineage_1, lineage_2) in arbitrary_distinct_lineages(),
        version in arbitrary_version(),
        entries_1 in arbitrary_batch(),
        entries_2 in arbitrary_batch(),
        updates_1 in arbitrary_batch(),
        updates_2 in arbitrary_batch(),
        query_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage_1, version, entries_1.clone()).map_err(to_fail)?;
        forest.add_lineage(lineage_2, version, entries_2.clone()).map_err(to_fail)?;

        let tree_1_v1 = build_tree(entries_1.clone())?;
        let tree_2_v1 = build_tree(entries_2.clone())?;

        let mut expected_tree_1 = tree_1_v1.clone();
        let mut expected_tree_2 = tree_2_v1.clone();
        apply_batch(&mut expected_tree_1, updates_1.clone())?;
        apply_batch(&mut expected_tree_2, updates_2.clone())?;

        let mut forest_updates = SmtForestUpdateBatch::empty();
        forest_updates.add_operations(
            lineage_1,
            updates_1.clone().into_iter(),
        );
        forest_updates.add_operations(
            lineage_2,
            updates_2.clone().into_iter(),
        );
        let results = forest.update_forest(version + 1, forest_updates).map_err(to_fail)?;
        prop_assert_eq!(results.len(), 2);

        let mut sample_keys = batch_keys(&entries_1);
        sample_keys.extend(batch_keys(&entries_2));
        sample_keys.extend(batch_keys(&updates_1));
        sample_keys.extend(batch_keys(&updates_2));
        sample_keys.push(query_key);
        sample_keys.sort();
        sample_keys.dedup();

        let versions_1 = if expected_tree_1.root() == tree_1_v1.root() {
            vec![(version, tree_1_v1.root())]
        } else {
            vec![(version, tree_1_v1.root()), (version + 1, expected_tree_1.root())]
        };
        let versions_2 = if expected_tree_2.root() == tree_2_v1.root() {
            vec![(version, tree_2_v1.root())]
        } else {
            vec![(version, tree_2_v1.root()), (version + 1, expected_tree_2.root())]
        };

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, versions_1.last().expect("non-empty").0),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, versions_2.last().expect("non-empty").0),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
        assert_lineage_metadata(&forest, lineage_1, &versions_1)?;
        assert_lineage_metadata(&forest, lineage_2, &versions_2)?;

        let roots = forest
            .roots()
            .map(|root| (root.lineage(), root.value()))
            .sorted()
            .collect_vec();
        let mut expected_roots =
            versions_1.iter().map(|(_, root)| (lineage_1, *root)).collect_vec();
        expected_roots.extend(versions_2.iter().map(|(_, root)| (lineage_2, *root)));
        expected_roots.sort();
        prop_assert_eq!(roots, expected_roots);
        prop_assert_eq!(forest.lineage_count(), 2);
        prop_assert_eq!(forest.tree_count(), versions_1.len() + versions_2.len());

        let unknown_lineage = LineageId::new([0x55; 32]);
        prop_assume!(unknown_lineage != lineage_1 && unknown_lineage != lineage_2);
        let mut invalid_updates = SmtForestUpdateBatch::empty();
        let invalid_value = Word::from([1u32, 1, 1, 1]);
        invalid_updates.add_operations(
            lineage_1,
            SmtUpdateBatch::new([ForestOperation::insert(query_key, invalid_value)].into_iter())
                .into_iter(),
        );
        invalid_updates
            .operations(unknown_lineage)
            .add_insert(query_key, invalid_value);
        let invalid_result = forest.update_forest(version + 2, invalid_updates);
        prop_assert!(invalid_result.is_err());

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, versions_1.last().expect("non-empty").0),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, versions_2.last().expect("non-empty").0),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
    }

    /// This test validates constructor behavior when loading from a pre-populated backend. The
    /// forest should load the latest tree state, but not reconstruct historical versions.
    #[test]
    fn new_loads_latest_backend_state_without_history(
        (lineage_1, lineage_2) in arbitrary_distinct_lineages(),
        version in arbitrary_version(),
        entries_1 in arbitrary_batch(),
        entries_2 in arbitrary_batch(),
        updates_1 in arbitrary_batch(),
        query_key in arbitrary_word(),
    ) {
        let mut backend = ForestInMemoryBackend::new();
        backend.add_lineage(lineage_1, version, entries_1.clone()).map_err(to_fail)?;
        backend.add_lineage(lineage_2, version, entries_2.clone()).map_err(to_fail)?;
        backend.update_tree(lineage_1, version + 1, updates_1.clone()).map_err(to_fail)?;

        let forest = LargeSmtForest::new(backend).map_err(to_fail)?;

        let tree_1_v1 = build_tree(entries_1.clone())?;
        let mut expected_tree_1 = tree_1_v1.clone();
        apply_batch(&mut expected_tree_1, updates_1.clone())?;
        let expected_tree_2 = build_tree(entries_2.clone())?;
        let latest_version_1 = if expected_tree_1.root() == tree_1_v1.root() {
            version
        } else {
            version + 1
        };

        let mut sample_keys = batch_keys(&entries_1);
        sample_keys.extend(batch_keys(&entries_2));
        sample_keys.extend(batch_keys(&updates_1));
        sample_keys.push(query_key);
        sample_keys.sort();
        sample_keys.dedup();

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, latest_version_1),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, version),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.lineage_count(), 2);
        prop_assert_eq!(forest.tree_count(), 2);
        prop_assert_eq!(forest.latest_version(lineage_1), Some(latest_version_1));
        prop_assert_eq!(forest.latest_root(lineage_1), Some(expected_tree_1.root()));
        let expected_root_info = if latest_version_1 == version {
            RootInfo::Missing
        } else {
            RootInfo::LatestVersion(expected_tree_1.root())
        };
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage_1, version + 1)),
            expected_root_info
        );
    }

    /// This test validates history retention under custom configuration and the semantics of
    /// explicit truncation.
    #[test]
    fn with_config_and_truncate_limit_retained_versions(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        key_1 in arbitrary_word(),
        key_2 in arbitrary_word(),
        key_3 in arbitrary_word(),
        key_4 in arbitrary_word(),
        value_1 in arbitrary_non_empty_word(),
        value_2 in arbitrary_non_empty_word(),
        value_3 in arbitrary_non_empty_word(),
        value_4 in arbitrary_non_empty_word(),
    ) {
        prop_assume!(key_1 != key_2 && key_1 != key_3 && key_1 != key_4);
        prop_assume!(key_2 != key_3 && key_2 != key_4);
        prop_assume!(key_3 != key_4);

        let config = ForestConfig::default().with_max_history_versions(2);
        let mut forest =
            LargeSmtForest::with_config(ForestInMemoryBackend::new(), config).map_err(to_fail)?;
        forest
            .add_lineage(
                lineage,
                version,
                SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 1,
                SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 2,
                SmtUpdateBatch::new([ForestOperation::insert(key_3, value_3)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 3,
                SmtUpdateBatch::new([ForestOperation::insert(key_4, value_4)].into_iter()),
            )
            .map_err(to_fail)?;

        let mut tree_v1 = Smt::new();
        apply_batch(
            &mut tree_v1,
            SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
        )?;
        let mut tree_v2 = tree_v1.clone();
        apply_batch(
            &mut tree_v2,
            SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
        )?;
        let mut tree_v3 = tree_v2.clone();
        apply_batch(
            &mut tree_v3,
            SmtUpdateBatch::new([ForestOperation::insert(key_3, value_3)].into_iter()),
        )?;
        let mut tree_v4 = tree_v3.clone();
        apply_batch(
            &mut tree_v4,
            SmtUpdateBatch::new([ForestOperation::insert(key_4, value_4)].into_iter()),
        )?;

        let sample_keys = vec![key_1, key_2, key_3, key_4];
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 2),
            &tree_v3,
            &sample_keys,
            false,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(forest.latest_root(lineage), Some(tree_v4.root()));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 2)),
            RootInfo::HistoricalVersion(tree_v3.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version)), RootInfo::Missing);

        forest.truncate(version + 2);
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 2),
            &tree_v3,
            &sample_keys,
            false,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 2)),
            RootInfo::HistoricalVersion(tree_v3.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 1)), RootInfo::Missing);

        forest.truncate(version + 3);
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(forest.latest_root(lineage), Some(tree_v4.root()));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 2)), RootInfo::Missing);
    }
}
