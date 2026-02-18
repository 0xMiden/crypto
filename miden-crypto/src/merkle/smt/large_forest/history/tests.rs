#![cfg(test)]
//! The functional tests for the history component.

use alloc::vec::Vec;
use core::iter::once;

use itertools::Itertools;

use super::{CompactLeaf, History, LeafChanges, NodeChanges, error::Result};
use crate::{
    EMPTY_WORD, Felt, Word,
    merkle::{
        NodeIndex,
        smt::{LeafIndex, Smt, VersionId, large_forest::root::TreeEntry},
    },
    rand::test_utils::ContinuousRng,
};

// TESTS
// ================================================================================================

#[test]
fn empty() {
    let history = History::empty(5);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 5);
}

#[test]
fn roots() -> Result<()> {
    let mut rng = ContinuousRng::new([0x12; 32]);

    // Set up our test state
    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();
    let mut history = History::empty(2);
    let root_1: Word = rng.value();
    let root_2: Word = rng.value();
    history.add_version(root_1, 0, nodes.clone(), leaves.clone())?;
    history.add_version(root_2, 1, nodes.clone(), leaves.clone())?;

    // We should be able to get all the roots.
    let roots = history.roots().collect::<Vec<_>>();
    assert_eq!(roots.len(), 2);
    assert!(roots.contains(&root_1));
    assert!(roots.contains(&root_2));

    Ok(())
}

#[test]
fn find_latest_corresponding_version() -> Result<()> {
    let mut rng = ContinuousRng::new([0x14; 32]);

    // Start by setting up our test data.
    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();
    let mut history = History::empty(5);

    let v1 = 10;
    let v2 = 20;
    let v3 = 30;
    let v4 = 31;
    let v5 = 45;

    history.add_version(rng.value(), v1, nodes.clone(), leaves.clone())?;
    history.add_version(rng.value(), v2, nodes.clone(), leaves.clone())?;
    history.add_version(rng.value(), v3, nodes.clone(), leaves.clone())?;
    history.add_version(rng.value(), v4, nodes.clone(), leaves.clone())?;
    history.add_version(rng.value(), v5, nodes.clone(), leaves.clone())?;

    // When we query for a version that is older than the oldest in the history we should get an
    // error.
    assert!(history.find_latest_corresponding_version(0).is_err());
    assert!(history.find_latest_corresponding_version(9).is_err());

    // When we query for the oldest version we should get its index.
    assert_eq!(history.find_latest_corresponding_version(v1), Ok(0));

    // And that goes for any other known version
    assert_eq!(history.find_latest_corresponding_version(v2), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(v3), Ok(2));
    assert_eq!(history.find_latest_corresponding_version(v4), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(v5), Ok(4));

    // But we can also query for versions in between.
    assert_eq!(history.find_latest_corresponding_version(11), Ok(0));
    assert_eq!(history.find_latest_corresponding_version(19), Ok(0));
    assert_eq!(history.find_latest_corresponding_version(21), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(29), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(32), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(44), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(46), Ok(4));

    Ok(())
}

#[test]
fn add_version() -> Result<()> {
    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();
    let mut rng = ContinuousRng::new([0x15; 32]);

    // We start with an empty state, and we should be able to add deltas up until the limit we
    // set.
    let mut history = History::empty(2);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 2);

    let root_1: Word = rng.value();
    let id_1 = 0;
    history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;
    assert_eq!(history.num_versions(), 1);

    let root_2: Word = rng.value();
    let id_2 = 1;
    history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;
    assert_eq!(history.num_versions(), 2);

    // At this point, adding any version should remove the oldest.
    let root_3: Word = rng.value();
    let id_3 = 2;
    history.add_version(root_3, id_3, nodes.clone(), leaves.clone())?;
    assert_eq!(history.num_versions(), 2);

    // If we then query for that first version it won't be there anymore, but the other two
    // should.
    assert!(history.get_view_at(id_1).is_err());
    assert!(history.get_view_at(id_2).is_ok());
    assert!(history.get_view_at(id_3).is_ok());

    // If we try and add a version with a non-monotonic version number, we should see an error.
    assert!(history.add_version(root_3, id_1, nodes, leaves).is_err());

    Ok(())
}

#[test]
fn add_version_from_mutation_set() -> Result<()> {
    let mut rng = ContinuousRng::new([0x16; 32]);

    // We start by producing values.
    let l1_k1: Word = rng.value();
    let leaf_1_ix = LeafIndex::from(l1_k1);
    let l1_v1: Word = rng.value();
    let mut l1_k2: Word = rng.value();
    l1_k2[3] = Felt::new(leaf_1_ix.position());
    let l1_v2: Word = rng.value();

    let l2_k1: Word = rng.value();
    let leaf_2_ix = LeafIndex::from(l2_k1);
    let l2_v1: Word = rng.value();
    let mut l2_k2: Word = rng.value();
    l2_k2[3] = Felt::new(leaf_2_ix.position());
    let l2_v2: Word = rng.value();

    // We produce a changeset by applying these changes to a merkle tree to put things back in the
    // right state.
    let tree = Smt::new();
    let mutations = tree
        .compute_mutations([(l1_k1, l1_v1), (l1_k2, l1_v2), (l2_k1, l2_v1), (l2_k2, l2_v2)])
        .expect("Failed to compute mutations");

    // We then set up our history and apply it.
    let mut history = History::empty(2);
    let version: VersionId = rng.value();

    history.add_version_from_mutation_set(version, mutations)?;

    // Now we can check that it did things correctly.
    let view = history.get_view_at(version)?;
    let expected_leaf_1 = CompactLeaf::from([(l1_k1, l1_v1), (l1_k2, l1_v2)]);
    assert_eq!(view.leaf_delta(&leaf_1_ix), expected_leaf_1);
    let expected_leaf_2 = CompactLeaf::from([(l2_k1, l2_v1), (l2_k2, l2_v2)]);
    assert_eq!(view.leaf_delta(&leaf_2_ix), expected_leaf_2);

    Ok(())
}

#[test]
fn truncate() -> Result<()> {
    let mut rng = ContinuousRng::new([0x17; 32]);

    // Start by setting up the test data
    let mut history = History::empty(4);

    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();

    let root_1: Word = rng.value();
    let id_1 = 5;
    history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

    let root_2: Word = rng.value();
    let id_2 = 10;
    history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

    let root_3: Word = rng.value();
    let id_3 = 15;
    history.add_version(root_3, id_3, nodes.clone(), leaves.clone())?;

    let root_4: Word = rng.value();
    let id_4 = 20;
    history.add_version(root_4, id_4, nodes.clone(), leaves.clone())?;

    assert_eq!(history.num_versions(), 4);

    // If we truncate to the oldest version or before, nothing should be removed.
    assert_eq!(history.truncate(0), 0);
    assert_eq!(history.num_versions(), 4);
    assert_eq!(history.truncate(4), 0);
    assert_eq!(history.num_versions(), 4);
    assert_eq!(history.truncate(id_1), 0);
    assert_eq!(history.num_versions(), 4);

    // If we truncate to a specific known version, it should remove all previous versions.
    assert_eq!(history.truncate(id_2), 1);
    assert_eq!(history.num_versions(), 3);

    // If we truncate to a version that is not known, the newest relevant version should be
    // retained.
    assert_eq!(history.truncate(16), 1);
    assert_eq!(history.num_versions(), 2);

    // If we truncate to a version beyond the newest known, only that should be retained.
    assert_eq!(history.truncate(25), 1);
    assert_eq!(history.num_versions(), 1);

    Ok(())
}

#[test]
fn clear() -> Result<()> {
    let mut rng = ContinuousRng::new([0x18; 32]);

    // Start by setting up the test data
    let mut history = History::empty(4);

    let nodes = NodeChanges::default();
    let leaves = LeafChanges::default();

    let root_1: Word = rng.value();
    let id_1 = 0;
    history.add_version(root_1, id_1, nodes.clone(), leaves.clone())?;

    let root_2: Word = rng.value();
    let id_2 = 1;
    history.add_version(root_2, id_2, nodes.clone(), leaves.clone())?;

    assert_eq!(history.num_versions(), 2);

    // We can clear the history entirely in one go.
    history.clear();
    assert_eq!(history.num_versions(), 0);

    Ok(())
}

#[test]
fn view_at() -> Result<()> {
    // Starting in an empty state we should be able to add deltas up until the limit we set.
    let mut history = History::empty(3);
    let mut rng = ContinuousRng::new([0x19; 32]);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 3);

    // We can add an initial version with some changes in both nodes and leaves.
    let root_1: Word = rng.value();
    let id_1 = 3;
    let mut nodes_1 = NodeChanges::default();
    let n1_value: Word = rng.value();
    let n2_value: Word = rng.value();
    nodes_1.insert(NodeIndex::new(2, 1).unwrap(), n1_value);
    nodes_1.insert(NodeIndex::new(8, 128).unwrap(), n2_value);

    let mut leaf_1 = CompactLeaf::new();
    let l1_e1_key: Word = rng.value();
    let l1_e1_value: Word = rng.value();
    let leaf_1_ix = LeafIndex::from(l1_e1_key);
    leaf_1.insert(l1_e1_key, l1_e1_value);

    let mut leaf_2 = CompactLeaf::new();
    let l2_e1_key: Word = rng.value();
    let l2_e1_value: Word = rng.value();
    let leaf_2_ix = LeafIndex::from(l2_e1_key);
    let mut l2_e2_key: Word = rng.value();
    l2_e2_key[3] = Felt::new(leaf_2_ix.position());
    let l2_e2_value: Word = rng.value();
    leaf_2.insert(l2_e1_key, l2_e1_value);
    leaf_2.insert(l2_e2_key, l2_e2_value);

    let mut leaves_1 = LeafChanges::default();
    leaves_1.insert(leaf_1_ix, leaf_1.clone());
    leaves_1.insert(leaf_2_ix, leaf_2.clone());

    history.add_version(root_1, id_1, nodes_1.clone(), leaves_1.clone())?;
    assert_eq!(history.num_versions(), 1);

    // We then add another version that overlaps with the older version.
    let root_2: Word = rng.value();
    let id_2 = 5;

    let mut nodes_2 = NodeChanges::default();
    let n3_value: Word = rng.value();
    let n4_value: Word = rng.value();
    nodes_2.insert(NodeIndex::new(2, 1).unwrap(), n3_value);
    nodes_2.insert(NodeIndex::new(10, 256).unwrap(), n4_value);

    let mut leaf_3 = CompactLeaf::new();
    let leaf_3_ix = leaf_2_ix;
    let mut l3_e1_key: Word = rng.value();
    l3_e1_key[3] = Felt::new(leaf_3_ix.position());
    let l3_e1_value: Word = rng.value();
    leaf_3.insert(l3_e1_key, l3_e1_value);

    let mut leaves_2 = LeafChanges::default();
    leaves_2.insert(leaf_3_ix, leaf_3.clone());
    history.add_version(root_2, id_2, nodes_2.clone(), leaves_2.clone())?;
    assert_eq!(history.num_versions(), 2);

    // And another version for the sake of the test.
    let root_3: Word = rng.value();
    let id_3 = 6;

    let mut nodes_3 = NodeChanges::default();
    let n5_value: Word = rng.value();
    nodes_3.insert(NodeIndex::new(30, 1).unwrap(), n5_value);

    let mut leaf_4 = CompactLeaf::new();
    let l4_e1_key: Word = rng.value();
    let l4_e1_value: Word = rng.value();
    let leaf_4_ix = LeafIndex::from(l4_e1_key);
    leaf_4.insert(l4_e1_key, l4_e1_value);

    let mut leaf_1n = CompactLeaf::new();
    let l1n_e1_key = l1_e1_key;
    let l1n_e1_value: Word = rng.value();
    leaf_1n.insert(l1n_e1_key, l1n_e1_value);

    let mut leaves_3 = LeafChanges::default();
    leaves_3.insert(leaf_4_ix, leaf_4.clone());
    leaves_3.insert(leaf_1_ix, leaf_1n);

    history.add_version(root_3, id_3, nodes_3.clone(), leaves_3.clone())?;
    assert_eq!(history.num_versions(), 3);

    // At this point, we can grab a view into the history. If we grab something older than the
    // history knows about we should get an error.
    assert!(history.get_view_at(2).is_err());

    // If we grab something valid, then we should get the right results. Let's grab the oldest
    // possible version to test the overlay logic.
    let view = history.get_view_at(id_1)?;

    // Getting a node in the targeted version should just return it.
    assert_eq!(view.node_value(&NodeIndex::new(2, 1).unwrap()), Some(&n1_value));
    assert_eq!(view.node_value(&NodeIndex::new(8, 128).unwrap()), Some(&n2_value));

    // Getting a node that is _not_ in the targeted delta directly should search through the
    // versions in between the targeted version at the current tree and return the oldest value
    // it can find for it.
    assert_eq!(view.node_value(&NodeIndex::new(10, 256).unwrap()), Some(&n4_value));
    assert_eq!(view.node_value(&NodeIndex::new(30, 1).unwrap()), Some(&n5_value));

    // Getting a node that doesn't exist in ANY versions should return none.
    assert!(view.node_value(&NodeIndex::new(45, 100).unwrap()).is_none());

    // Getting a leaf from the targeted version will compose with other (newer) deltas to yield the
    // correct changes. The first test here checks that a value updated in a newer delta is
    // nevertheless reverted to the correct value.
    assert_eq!(view.leaf_delta(&leaf_1_ix), leaf_1);

    // This test checks that the delta for a single leaf correctly combines non-overlapping key
    // reversions.
    let leaf_2_delta: CompactLeaf = once((l3_e1_key, l3_e1_value))
        .chain(leaf_2.iter().map(|(k, v)| (*k, *v)))
        .collect();
    assert_eq!(view.leaf_delta(&leaf_2_ix), leaf_2_delta);

    // But getting a leaf that is not in the target delta directly should result in the same
    // traversal.
    assert_eq!(view.leaf_delta(&leaf_4_ix), leaf_4);

    // And getting a leaf that does not exist in any of the versions should return an empty delta.
    assert!(view.leaf_delta(&LeafIndex::new(1024).unwrap()).is_empty());

    // Finally, getting a full value from a compact leaf should yield the value directly from
    // the target version if the target version overlays it AND contains it.
    assert_eq!(view.value(&l1_e1_key), Some(l1_e1_value));
    assert_eq!(view.value(&l2_e1_key), Some(l2_e1_value));
    assert_eq!(view.value(&l2_e2_key), Some(l2_e2_value));

    // However, if the leaf exists but does not contain the provided word, it should return the
    // sentinel `Some(None)`.
    let mut ne_key_in_existing_leaf: Word = rng.value();
    ne_key_in_existing_leaf[3] = Felt::new(leaf_1_ix.position());
    assert_eq!(view.value(&ne_key_in_existing_leaf), None);

    // If the leaf is not overlaid, then the lookup should go up the chain just as in the other
    // cases.
    assert_eq!(view.value(&l4_e1_key), Some(l4_e1_value));

    // But if nothing is found, it should just return None;
    let ne_key: Word = rng.value();
    assert!(view.value(&ne_key).is_none());

    // We can also get views for versions that are not directly contained, such as a version newer
    // than the newest. This should just use the newest version to service the query.
    let view = history.get_view_at(7)?;
    assert_eq!(view.node_value(&NodeIndex::new_unchecked(30, 1)), Some(&n5_value));
    assert!(view.node_value(&NodeIndex::new_unchecked(30, 2)).is_none());

    // We can also get an iterator over the entries for a given view. This should yield all the
    // correctly-collapsed key-value pairs in the overlay. We start with the most recent view.
    let view = history.get_view_at(id_3)?;
    assert_eq!(view.entries().count(), 2);
    assert!(view.entries().contains(&TreeEntry { key: l4_e1_key, value: l4_e1_value }));
    assert!(view.entries().contains(&TreeEntry { key: l1n_e1_key, value: l1n_e1_value }));
    assert!(view.entries().is_sorted_by(|l, r| {
        if l.index() == r.index() {
            l.key < r.key
        } else {
            l.index() < r.index()
        }
    }));

    Ok(())
}

// SMT INTEGRATION TESTS
// ================================================================================================

/// Tests History integration using real SMT mutations.
///
/// This test creates an actual SMT, computes mutations via the SMT API,
/// and verifies that History correctly tracks the resulting node and leaf changes.
#[test]
fn history_from_smt_non_overlapping() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1a; 32]);

    // Create an empty SMT
    let mut smt = Smt::new();
    let initial_root = smt.root();

    // Generate test key-value pairs
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    // Create history to track versions
    let mut history = History::empty(3);

    // Version 0: Insert first key-value pair using real SMT mutation while getting the reversion
    // set for the history.
    let mutations_v0 = smt.compute_mutations(vec![(key_1, value_1)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v0).unwrap();
    let root_v0 = smt.root();
    history.add_version_from_mutation_set(0, reversion_set)?;
    assert_eq!(history.num_versions(), 1);

    // Version 1: Insert second key-value pair
    let mutations_v1 = smt.compute_mutations(vec![(key_2, value_2)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v1).unwrap();
    let root_v1 = smt.root();
    history.add_version_from_mutation_set(1, reversion_set)?;

    // Verify the roots for older states are tracked correctly in the history.
    assert!(history.is_known_root(initial_root));
    assert!(history.is_known_root(root_v0));

    // And that the latest root of the tree is not.
    assert!(!history.is_known_root(root_v1));

    // We can start by checking that version 0 performs the correct reversion operations,
    // encompassing _both_ changes made to obtain the current version.
    let view_v0 = history.get_view_at(0)?;
    assert_eq!(view_v0.value(&key_1), Some(EMPTY_WORD));
    assert_eq!(view_v0.value(&key_2), Some(EMPTY_WORD));
    assert_eq!(view_v0.leaf_delta(&key_1.into()).len(), 1);
    assert_eq!(view_v0.leaf_delta(&key_2.into()).len(), 1);

    // When we query version 1 it should only make revert one change on top of the current tree.
    let view_v1 = history.get_view_at(1)?;
    assert_eq!(view_v0.value(&key_2), Some(EMPTY_WORD));
    assert_eq!(view_v0.leaf_delta(&key_2.into()).len(), 1);

    // Verify querying a non-existent key returns None
    let nonexistent_key: Word = rng.value();
    assert!(view_v1.value(&nonexistent_key).is_none());

    Ok(())
}

/// Tests History with SMT value updates (replacing existing values).
#[test]
fn history_from_smt_overlapping() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1b; 32]);
    let mut smt = Smt::new();

    let key: Word = rng.value();
    let value_v0: Word = rng.value();
    let value_v1: Word = rng.value();

    let mut history = History::empty(2);

    // Version 0: Insert initial value
    let mutations_v0 = smt.compute_mutations(vec![(key, value_v0)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v0).unwrap();
    history.add_version_from_mutation_set(0, reversion_set)?;

    // Version 1: Update to new value
    let mutations_v1 = smt.compute_mutations(vec![(key, value_v1)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v1).unwrap();
    history.add_version_from_mutation_set(1, reversion_set)?;

    // In version 0 we should have the correct (empty) value when reverted.
    let view_v0 = history.get_view_at(0)?;
    assert_eq!(view_v0.value(&key), Some(EMPTY_WORD));

    // In version 1 we should have the value set in the transition to version 0.
    let view_v1 = history.get_view_at(1)?;
    assert_eq!(view_v1.value(&key), Some(value_v0));

    Ok(())
}
