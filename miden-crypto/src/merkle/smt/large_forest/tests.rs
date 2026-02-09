//! This module contains the handwritten tests for the SMT forest.

#![cfg(all(test, feature = "std"))]

use alloc::vec::Vec;

use super::{
    LargeSmtForest, LineageData,
    backend::{self, Backend, MutationSet},
    history::{History, LeafChanges, NodeChanges},
    operation::{SmtForestUpdateBatch, SmtUpdateBatch},
    root::{LineageId, RootValue, TreeEntry, TreeId, VersionId},
};
use crate::{Map, Set, Word, merkle::smt::SmtProof, rand::test_utils::rand_value};

// MOCK BACKEND
// ================================================================================================

/// A minimal mock backend for testing forest methods that do not touch the backend.
#[derive(Debug)]
struct MockBackend;

impl Backend for MockBackend {
    fn open(&self, _: LineageId, _: Word) -> backend::Result<SmtProof> {
        unimplemented!("not needed for this test")
    }

    fn get(&self, _: LineageId, _: Word) -> backend::Result<Option<Word>> {
        unimplemented!("not needed for this test")
    }

    fn version(&self, _: LineageId) -> backend::Result<VersionId> {
        unimplemented!("not needed for this test")
    }

    fn lineages(&self) -> backend::Result<impl Iterator<Item = LineageId>> {
        Ok(core::iter::empty())
    }

    fn trees(&self) -> backend::Result<impl Iterator<Item = (TreeId, RootValue)>> {
        Ok(core::iter::empty())
    }

    fn entry_count(&self, _: TreeId) -> backend::Result<usize> {
        unimplemented!("not needed for this test")
    }

    fn entries(&self, _: TreeId) -> backend::Result<impl Iterator<Item = TreeEntry>> {
        Ok(core::iter::empty())
    }

    fn update_tree(
        &mut self,
        _: LineageId,
        _: VersionId,
        _: SmtUpdateBatch,
    ) -> backend::Result<MutationSet> {
        unimplemented!("not needed for this test")
    }

    fn update_forest(
        &mut self,
        _: VersionId,
        _: SmtForestUpdateBatch,
    ) -> backend::Result<Vec<MutationSet>> {
        unimplemented!("not needed for this test")
    }
}

// TESTS
// ================================================================================================

/// Regression test: `truncate` must remove lineages whose histories become empty from
/// `non_empty_histories`. Previously, `extend` was used instead of `remove`, which caused emptied
/// lineages to be incorrectly retained (or even duplicated) in the set.
#[test]
fn truncate_removes_emptied_lineages_from_non_empty_histories() {
    let lineage: LineageId = rand_value();
    let root: Word = rand_value();

    // Build a lineage with one historical version at version 5, and a latest version of 10.
    let mut history = History::empty(4);
    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();
    history.add_version(rand_value(), 5, nodes, leaves).unwrap();
    assert_eq!(history.num_versions(), 1);

    let lineage_data = LineageData {
        history,
        latest_version: 10,
        latest_root: root,
    };

    let mut lineage_map = Map::default();
    lineage_map.insert(lineage, lineage_data);

    let mut non_empty = Set::default();
    non_empty.insert(lineage);

    let mut forest = LargeSmtForest {
        backend: MockBackend,
        lineage_data: lineage_map,
        non_empty_histories: non_empty,
    };

    // Sanity: the lineage is tracked as having a non-empty history.
    assert!(forest.non_empty_histories.contains(&lineage));

    // Truncate to a version >= latest_version, which clears the history entirely.
    forest.truncate(10);

    // The lineage's history should now be empty, and it must have been removed from the set.
    assert!(
        !forest.non_empty_histories.contains(&lineage),
        "emptied lineage must be removed from non_empty_histories after truncation"
    );
}

/// Verifies that `truncate` retains lineages in `non_empty_histories` when their history is only
/// partially truncated and still contains versions.
#[test]
fn truncate_retains_non_empty_lineages_in_non_empty_histories() {
    let lineage: LineageId = rand_value();
    let root: Word = rand_value();

    // Build a lineage with two historical versions (5 and 8), latest version 15.
    let mut history = History::empty(4);
    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();
    history.add_version(rand_value(), 5, nodes.clone(), leaves.clone()).unwrap();
    history.add_version(rand_value(), 8, nodes, leaves).unwrap();
    assert_eq!(history.num_versions(), 2);

    let lineage_data = LineageData {
        history,
        latest_version: 15,
        latest_root: root,
    };

    let mut lineage_map = Map::default();
    lineage_map.insert(lineage, lineage_data);

    let mut non_empty = Set::default();
    non_empty.insert(lineage);

    let mut forest = LargeSmtForest {
        backend: MockBackend,
        lineage_data: lineage_map,
        non_empty_histories: non_empty,
    };

    // Truncate to version 7: removes versions older than 7, but version 8 should remain.
    // Since version < latest_version (15), LineageData::truncate returns false.
    forest.truncate(7);

    // The history still has data, so the lineage must stay in non_empty_histories.
    assert!(
        forest.non_empty_histories.contains(&lineage),
        "lineage with remaining history must stay in non_empty_histories"
    );
}
