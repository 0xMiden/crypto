use assert_matches::assert_matches;
use itertools::Itertools;

use super::{EmptySubtreeRoots, MerkleError, SmtForest, Word};
use crate::{
    Felt, ONE, WORD_SIZE, ZERO,
    merkle::{
        int_to_node,
        smt::{SMT_DEPTH, SmtProofError},
    },
};

// TESTS
// ================================================================================================

#[test]
fn test_insert_root_not_in_store() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
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
    let mut forest = SmtForest::new();
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
    let mut forest = SmtForest::new();

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
    let forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    let values = vec![
        (Word::new([ZERO; WORD_SIZE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ONE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ZERO]), Word::new([ONE; WORD_SIZE])),
    ];

    values.into_iter().permutations(3).for_each(|values| {
        let mut forest = forest.clone();
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
            proof.verify_presence(&key, &value, &new_root).unwrap();
        }
    });

    Ok(())
}

#[test]
fn test_open_root_not_in_store() -> Result<(), MerkleError> {
    let forest = SmtForest::new();
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
    let mut forest = SmtForest::new();

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
    proof
        .verify_presence(
            &Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
            &int_to_node(3),
            &root,
        )
        .expect("proof should verify membership");

    Ok(())
}

#[test]
fn test_multiple_versions_of_same_key() -> Result<(), MerkleError> {
    // Verify that when we insert multiple values for the same key,
    // we can still open valid proofs for all historical roots.
    let mut forest = SmtForest::new();

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
    proof1
        .verify_presence(&key, &value1, &root1)
        .expect("Proof for root1 should verify with value1");

    let proof2 = forest.open(root2, key)?;
    proof2
        .verify_presence(&key, &value2, &root2)
        .expect("Proof for root2 should verify with value2");

    let proof3 = forest.open(root3, key)?;
    proof3
        .verify_presence(&key, &value3, &root3)
        .expect("Proof for root3 should verify with value3");

    // Wrong values cannot be verified - should return ValueMismatch
    assert_matches!(
        proof1.verify_presence(&key, &value2, &root1),
        Err(SmtProofError::ValueMismatch { .. }),
        "Proof for root1 should not verify with value2"
    );

    assert_matches!(
        proof3.verify_presence(&key, &value1, &root3),
        Err(SmtProofError::ValueMismatch { .. }),
        "Proof for root3 should not verify with value1"
    );

    Ok(())
}

#[test]
fn test_pop_roots() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);
    let value = Word::new([ONE; WORD_SIZE]);
    let root = forest.insert(empty_tree_root, key, value)?;

    assert_eq!(forest.roots.len(), 1);
    assert_eq!(forest.leaves.len(), 1);

    forest.pop_smts(vec![root]);

    assert_eq!(forest.roots.len(), 0);
    assert_eq!(forest.leaves.len(), 0);

    Ok(())
}

#[test]
fn test_removing_empty_smt_from_forest() {
    let mut forest = SmtForest::new();
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let non_empty_root = Word::new([ONE; WORD_SIZE]);

    // Popping zero SMTs from forest should be a no-op (no panic or error)
    forest.pop_smts(vec![]);

    // Popping a non-existent root should be a no-op (no panic or error)
    forest.pop_smts(vec![non_empty_root]);

    // Popping the empty root should be a no-op (no panic or error)
    forest.pop_smts(vec![empty_tree_root]);
}
