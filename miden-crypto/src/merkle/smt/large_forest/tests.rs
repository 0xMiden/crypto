#![cfg(test)]
//! This module contains the handwritten tests of the functionality for the SMT forest. These tests
//! are for the basic functionality, and rely on the
//!
//! Wherever possible, these tests rely on the correctness of the existing [`Smt`] implementation.
//! It is used as a point of comparison to avoid the need to hard-code specific values and scenarios
//! for the trees, instead allowing us to compare things directly.

use alloc::vec::Vec;

use assert_matches::assert_matches;

use super::{Config, Result};
use crate::{
    Word,
    merkle::{
        EmptySubtreeRoots,
        smt::{
            Backend, ForestInMemoryBackend, ForestOperation, LargeSmtForest, LargeSmtForestError,
            LeafIndex, RootInfo, Smt, SmtUpdateBatch, TreeId, VersionId,
            large_forest::root::{LineageId, TreeWithRoot},
        },
    },
    rand::test_utils::ContinuousRng,
};
// TYPE ALIASES
// ================================================================================================

/// We only care about testing with the in-memory backend here for correct functionality.
type Forest = LargeSmtForest<ForestInMemoryBackend>;

// CONSTRUCTION TESTS
// ================================================================================================

#[test]
fn new() -> Result<()> {
    // Constructing a forest using the default constructor should yield the default configuration.
    let backend = ForestInMemoryBackend::new();
    let forest = Forest::new(backend)?;

    // We can just sanity-check the configuration to ensure that things started up right.
    let config = forest.get_config();

    assert_eq!(config.max_historical_versions, 10);

    Ok(())
}

#[test]
fn with_config() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let forest = Forest::with_config(backend, Config::default().with_max_history_versions(30))?;

    // Let us sanity check using the config again.
    let config = forest.get_config();

    assert_eq!(config.max_historical_versions, 30);

    Ok(())
}

// BASIC QUERIES TESTS
// ================================================================================================

#[test]
fn roots() -> Result<()> {
    // We start by constructing our forest.
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x96; 32]);

    // We add a number of lineages to the forest, some of which have the same _root_ value.
    let version_1: VersionId = rng.value();
    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();

    let root_1 = forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_1,
        TreeWithRoot::new(lineage_1, version_1, *EmptySubtreeRoots::entry(64, 0))
    );
    let root_2 = forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_2,
        TreeWithRoot::new(lineage_2, version_1, *EmptySubtreeRoots::entry(64, 0))
    );
    let root_3 = forest.add_lineage(lineage_3, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_3,
        TreeWithRoot::new(lineage_3, version_1, *EmptySubtreeRoots::entry(64, 0))
    );

    // We then update one of them to make sure it ends up with a historical root as well.
    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let k2: Word = rng.value();
    let v2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    operations.add_insert(k2, v2);

    let version_2: VersionId = version_1 + 1;
    let root_4 = forest.update_tree(lineage_1, version_2, operations)?;

    // We can now check that the roots iterator contains the items we expect.
    let roots = forest.roots().collect::<Vec<_>>();
    assert_eq!(roots.len(), 4);
    assert!(roots.contains(&root_1.into()));
    assert!(roots.contains(&root_2.into()));
    assert!(roots.contains(&root_3.into()));
    assert!(roots.contains(&root_4.into()));

    Ok(())
}

#[test]
fn latest_version() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x69; 32]);

    // Let's add some trees to the forest. Two are empty and one is added with data.
    let version_1: VersionId = rng.value();
    let version_2: VersionId = version_1 + 1;
    let version_3: VersionId = version_2 + 1;

    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let k2: Word = rng.value();
    let v2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    operations.add_insert(k2, v2);

    forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;
    forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;
    forest.add_lineage(lineage_3, version_1, operations)?;

    // Now let's update one of the empty ones twice...
    let k3: Word = rng.value();
    let v3: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k3, v3);
    forest.update_tree(lineage_1, version_2, operations)?;

    let k4: Word = rng.value();
    let v4: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k4, v4);
    forest.update_tree(lineage_1, version_3, operations)?;

    // ...and the non-empty one once with a non-contiguous version.
    let k5: Word = rng.value();
    let v5: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k5, v5);
    forest.update_tree(lineage_3, version_3, operations)?;

    // Now let's query the latest version for all of them.
    assert_eq!(forest.latest_version(lineage_1).unwrap(), version_3);
    assert_eq!(forest.latest_version(lineage_2).unwrap(), version_1);
    assert_eq!(forest.latest_version(lineage_3).unwrap(), version_3);

    // Finally, if we look for a lineage that doesn't exist, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.latest_version(ne_lineage).is_none());

    Ok(())
}

#[test]
fn lineage_roots() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x42; 32]);

    // Let's add a lineage to the forest and update it a few times.
    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let version_3 = version_2 + 1;
    let root_1 = forest.add_lineage(lineage, version_1, SmtUpdateBatch::default())?;

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    let root_2 = forest.update_tree(lineage, version_2, operations)?;

    let k2: Word = rng.value();
    let v2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k2, v2);
    let root_3 = forest.update_tree(lineage, version_3, operations)?;

    // Now we can query for the roots in this lineage.
    let lineage_roots = forest
        .lineage_roots(lineage)
        .expect("Existing lineage should have roots")
        .collect::<Vec<_>>();
    assert_eq!(lineage_roots.len(), 3);

    // For this method, the contract insists that it is ordered from newer roots in the lineage to
    // older roots.
    assert_eq!(lineage_roots[0], root_3.root());
    assert_eq!(lineage_roots[1], root_2.root());
    assert_eq!(lineage_roots[2], root_1.root());

    // If, however, we query for the roots of a non-existent lineage, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.lineage_roots(ne_lineage).is_none());

    Ok(())
}

#[test]
fn latest_root() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x97; 32]);

    // Let's add a lineage to the forest.
    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let root_1 = forest.add_lineage(lineage, version_1, SmtUpdateBatch::default())?;

    // We can get its latest root.
    assert_eq!(forest.latest_root(lineage), Some(root_1.root()));

    // And then update it...
    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    let root_2 = forest.update_tree(lineage, version_2, operations)?;

    // ...to check that we get the updated root.
    assert_eq!(forest.latest_root(lineage), Some(root_2.root()));

    // However, if we query for a nonexistent lineage, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.latest_root(ne_lineage).is_none());

    Ok(())
}

#[test]
fn tree_count() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x67; 32]);

    // A newly-initialized forest should know about only the trees that its backend knows about.
    assert_eq!(forest.tree_count(), forest.get_backend().trees()?.count());

    // Now let's add some trees.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let version_3 = version_2 + 1;
    forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    forest.update_tree(lineage_1, version_2, operations)?;

    let k2: Word = rng.value();
    let v2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k2, v2);
    forest.update_tree(lineage_1, version_3, operations)?;

    let lineage_2: LineageId = rng.value();
    forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;

    // As there are two current trees and two historical versions, we should see four trees total.
    assert_eq!(forest.tree_count(), 4);

    Ok(())
}

#[test]
fn lineage_count() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x64; 32]);

    // A newly-initialized forest should know about only the lineages that its backend knows about.
    assert_eq!(forest.lineage_count(), forest.get_backend().lineages()?.count());

    // So now let's add some lineages.
    let version: VersionId = rng.value();
    let lineage_1: LineageId = rng.value();
    forest.add_lineage(lineage_1, version, SmtUpdateBatch::default())?;
    let lineage_2: LineageId = rng.value();
    forest.add_lineage(lineage_2, version, SmtUpdateBatch::default())?;
    let lineage_3: LineageId = rng.value();
    forest.add_lineage(lineage_3, version, SmtUpdateBatch::default())?;

    // We should see three lineages.
    assert_eq!(forest.lineage_count(), 3);

    // This should stay the same if we update a tree.
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    forest.update_tree(lineage_1, version + 1, operations)?;
    assert_eq!(forest.lineage_count(), 3);

    Ok(())
}

#[test]
fn root_info() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x32; 32]);

    // Let's start by adding a lineage and updating it.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    let historical_root = forest.add_lineage(lineage_1, version_1, operations)?;

    let version_2 = version_1 + 1;
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    let current_root = forest.update_tree(lineage_1, version_2, operations)?;

    // When we query for a root (lineage_1, version_1), we should get back HistoricalVersion.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_1)),
        RootInfo::HistoricalVersion(historical_root.root())
    );

    // When we query for a root (lineage_1, version_2), we should get back LatestVersion.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_2)),
        RootInfo::LatestVersion(current_root.root())
    );

    // When we query for a nonexistent version in an existing lineage we should get back Missing.
    let version_3 = version_2 + 1;
    assert_eq!(forest.root_info(TreeId::new(lineage_1, version_3)), RootInfo::Missing);

    // As we should also get back when the lineage doesn't exist.
    let lineage_2: LineageId = rng.value();
    assert_eq!(forest.root_info(TreeId::new(lineage_2, version_1)), RootInfo::Missing);

    Ok(())
}

// QUERIES TESTS
// ================================================================================================

// TODO tests

// SINGLE-TREE MODIFIER TESTS
// ================================================================================================

#[test]
fn add_lineage() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x42; 32]);

    // We can add an initial lineage to the forest, starting with no changes from the default tree.
    let lineage: LineageId = rng.value();
    let version: VersionId = rng.value();
    let result = forest.add_lineage(lineage, version, SmtUpdateBatch::default());
    assert!(result.is_ok());

    // This should yield the correct value, which we'll check using a Smt.
    let tree = Smt::new();

    let result = result?;
    assert_eq!(result.root(), tree.root());
    assert_eq!(result.lineage(), lineage);
    assert_eq!(result.version(), version);

    // If we try and add a duplicated lineage again, we should get an error.
    let result = forest.add_lineage(lineage, version, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::DuplicateLineage(l) if l == lineage);

    Ok(())
}

#[test]
fn update_tree() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x69; 32]);

    // Let's start by adding a lineage to the forest...
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);

    let result = forest.add_lineage(lineage_1, version_1, operations)?;

    // ... and creating an auxiliary tree with the same value to check consistency.
    let mut tree = Smt::new();
    tree.insert(key_1, value_1)?;

    assert_eq!(result.root(), tree.root());

    // If we try and update a lineage that is unknown, we should see an error.
    let unknown_lineage: LineageId = rng.value();
    let result = forest.update_tree(unknown_lineage, version_1, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::UnknownLineage(l) if l == unknown_lineage
    );

    // If we add a version that is older than the latest known version for that lineage, we should
    // see an error.
    let older_version = version_1 - 1;
    let result = forest.update_tree(lineage_1, older_version, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::BadVersion(v1, v2) if v1 == older_version && v2 == version_1
    );

    // Let's create some data and actually add it.
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_2, value_2);
    operations.add_insert(key_3, value_3);
    operations.add_remove(key_1);

    let version_2: VersionId = rng.value();
    let result = forest.update_tree(lineage_1, version_2, operations)?;

    // And we can check this against the tree.
    let mutations =
        tree.compute_mutations(vec![(key_1, Word::empty()), (key_2, value_2), (key_3, value_3)])?;
    tree.apply_mutations(mutations)?;

    assert_eq!(result.root(), tree.root());

    // And we should also now have a history version that corresponds to the previous version, which
    // we are going to get at via some test helpers.
    let history = forest.get_history(lineage_1);
    assert_eq!(history.num_versions(), 1);

    // If we query for each value, we should see the correct reversions.
    let view = history.get_view_at(version_1)?;

    assert_eq!(view.leaf_delta(&LeafIndex::from(key_1)).get(&key_1), Some(&value_1));
    assert_eq!(view.leaf_delta(&LeafIndex::from(key_2)).get(&key_2), Some(&Word::empty()));
    assert_eq!(view.leaf_delta(&LeafIndex::from(key_3)).get(&key_3), Some(&Word::empty()));

    Ok(())
}
