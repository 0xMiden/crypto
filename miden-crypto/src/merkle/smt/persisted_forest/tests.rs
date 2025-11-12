use assert_matches::assert_matches;
use itertools::Itertools;

use super::*;
use crate::{
    Felt, ONE, WORD_SIZE, ZERO,
    merkle::{int_to_node, smt::SMT_DEPTH},
};
use tempfile::tempdir;

// TESTS
// ================================================================================================

#[test]
fn persisted_forest_survives_reopen() {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO, ZERO, ZERO, ZERO]);
    let value = Word::new([ONE, ZERO, ZERO, ZERO]);

    let new_root = forest.insert(empty_root, key, value).expect("insert into forest");
    let proof = forest.open(new_root, key).expect("open proof");
    assert!(proof.verify_membership(&key, &value, &new_root));

    drop(forest);

    let forest = PersistedSmtForest::new(config).expect("reopen forest");
    let reopened_proof = forest.open(new_root, key).expect("open proof after reopen");
    assert!(reopened_proof.verify_membership(&key, &value, &new_root));
}

#[test]
fn test_insert_root_not_in_store() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");
    let word = Word::new([ONE; WORD_SIZE]);
    assert_matches!(
        forest.insert(word, word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_insert_root_empty() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);
    let value = Word::new([ONE; WORD_SIZE]);
    assert_eq!(
        forest.insert(empty_tree_root, key, value)?,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );
    Ok(())
}

#[test]
fn test_insert_multiple_values() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);
    let value = Word::new([ONE; WORD_SIZE]);
    let new_root = forest.insert(empty_tree_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );

    let new_root = forest.insert(new_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );

    // Inserting the same key-value pair again should return the same root
    let root_duplicate = forest.insert(new_root, key, value)?;
    assert_eq!(new_root, root_duplicate);

    let key2 = Word::new([ZERO, ONE, ZERO, ONE]);
    let new_root = forest.insert(new_root, key2, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(1600265794710932756),
            Felt::new(4102884415474859847),
            Felt::new(7916203901318401823),
            Felt::new(9187865964280213047)
        ])
    );

    Ok(())
}

#[test]
fn test_batch_insert() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    let values = vec![
        (Word::new([ZERO; WORD_SIZE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ONE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ZERO]), Word::new([ONE; WORD_SIZE])),
    ];
    let new_root = forest.batch_insert(empty_tree_root, values.clone()).unwrap();

    assert_eq!(
        new_root,
        Word::new([
            Felt::new(7086678883692273722),
            Felt::new(12292668811816691012),
            Felt::new(10126815404170194367),
            Felt::new(1147037274136690014)
        ])
    );

    for (key, value) in values {
        let proof = forest.open(new_root, key).unwrap();
        assert!(proof.verify_membership(&key, &value, &new_root));
    }

    Ok(())
}

#[test]
fn test_open_root_not_in_store() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");
    let word = Word::new([ONE; WORD_SIZE]);
    assert_matches!(
        forest.open(word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_open_root_in_store() -> Result<(), MerkleError> {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

    let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
        int_to_node(1),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]),
        int_to_node(2),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
        int_to_node(3),
    )?;

    let proof =
        forest.open(root, Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]))?;
    assert!(proof.verify_membership(
        &Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
        &int_to_node(3),
        &root
    ));

    Ok(())
}

#[test]
fn test_multiple_versions_of_same_key() -> Result<(), MerkleError> {
    // Verify that when we insert multiple values for the same key,
    // we can still open valid proofs for all historical roots.
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);

    // Insert the same key with different values, creating multiple roots
    let value1 = Word::new([ONE; WORD_SIZE]);
    let root1 = forest.insert(empty_tree_root, key, value1)?;

    let value2 = Word::new([Felt::new(2); WORD_SIZE]);
    let root2 = forest.insert(root1, key, value2)?;

    let value3 = Word::new([Felt::new(3); WORD_SIZE]);
    let root3 = forest.insert(root2, key, value3)?;

    // All three roots should be different
    assert_ne!(root1, root2);
    assert_ne!(root2, root3);
    assert_ne!(root1, root3);

    // Open proofs for each historical root and verify them
    let proof1 = forest.open(root1, key)?;
    assert!(
        proof1.verify_membership(&key, &value1, &root1),
        "Proof for root1 should verify with value1"
    );

    let proof2 = forest.open(root2, key)?;
    assert!(
        proof2.verify_membership(&key, &value2, &root2),
        "Proof for root2 should verify with value2"
    );

    let proof3 = forest.open(root3, key)?;
    assert!(
        proof3.verify_membership(&key, &value3, &root3),
        "Proof for root3 should verify with value3"
    );

    // Wrong values cannot be verified
    assert!(
        !proof1.verify_membership(&key, &value2, &root1),
        "Proof for root1 should not verify with value2"
    );

    assert!(
        !proof3.verify_membership(&key, &value1, &root3),
        "Proof for root3 should not verify with value1"
    );

    Ok(())
}

// #[test]
// fn test_pop_roots() -> Result<(), MerkleError> {
//     let tmp = tempdir().expect("tempdir");
//     let config = RocksDbForestConfig::new(tmp.path());
//     let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");

//     let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
//     let key = Word::new([ZERO; WORD_SIZE]);
//     let value = Word::new([ONE; WORD_SIZE]);
//     let root = forest.insert(empty_tree_root, key, value)?;

//     assert_eq!(forest.roots.len(), 1);
//     assert_eq!(forest.leaves.len(), 1);

//     forest.pop_smts(vec![root]);

//     assert_eq!(forest.roots.len(), 0);
//     assert_eq!(forest.leaves.len(), 0);

//     Ok(())
// }

#[test]
fn test_removing_empty_smt_from_forest() {
    let tmp = tempdir().expect("tempdir");
    let config = RocksDbForestConfig::new(tmp.path());
    let mut forest = PersistedSmtForest::new(config.clone()).expect("create persisted forest");
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let non_empty_root = Word::new([ONE; WORD_SIZE]);

    // Popping zero SMTs from forest should be a no-op (no panic or error)
    forest.pop_smts(vec![]);

    // Popping a non-existent root should be a no-op (no panic or error)
    forest.pop_smts(vec![non_empty_root]);

    // Popping the empty root should be a no-op (no panic or error)
    forest.pop_smts(vec![empty_tree_root]);
}
