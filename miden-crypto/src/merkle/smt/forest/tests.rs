use assert_matches::assert_matches;

use super::{EmptySubtreeRoots, MerkleError, SmtForest, Word};
use crate::{
    Felt, ONE, WORD_SIZE, ZERO,
    merkle::{int_to_node, smt::SMT_DEPTH},
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
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    let values = vec![
        (Word::new([ZERO; WORD_SIZE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ZERO]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ONE]), Word::new([ONE; WORD_SIZE])),
    ];

    let new_root = forest.batch_insert(empty_tree_root, values.into_iter())?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(6703167280526557258),
            Felt::new(18389096225374738330),
            Felt::new(5605267564941856750),
            Felt::new(14623616106397295145)
        ])
    );

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
    assert_eq!(
        proof.verify_membership(
            &Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
            &int_to_node(3),
            &root
        ),
        true
    );

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
fn test_multiple_independent_trees() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    // Create first tree with some key-value pairs
    let key1 = Word::new([ZERO, ZERO, ZERO, ZERO]);
    let value1 = Word::new([ONE, ZERO, ZERO, ZERO]);
    let tree1_root = forest.insert(empty_tree_root, key1, value1)?;

    let key2 = Word::new([ZERO, ZERO, ZERO, ONE]);
    let value2 = Word::new([ONE, ONE, ZERO, ZERO]);
    let tree1_root = forest.insert(tree1_root, key2, value2)?;

    // Create second independent tree starting from empty root
    let key3 = Word::new([ZERO, ZERO, ONE, ZERO]);
    let value3 = Word::new([Felt::new(3), ZERO, ZERO, ZERO]);
    let tree2_root = forest.insert(empty_tree_root, key3, value3)?;

    let key4 = Word::new([ZERO, ZERO, ONE, ONE]);
    let value4 = Word::new([Felt::new(4), ZERO, ZERO, ZERO]);
    let tree2_root = forest.insert(tree2_root, key4, value4)?;

    // Verify all three roots are different
    assert_ne!(tree1_root, tree2_root, "Tree 1 and Tree 2 should have different roots");

    // Verify we can open and verify proofs from tree1
    let proof1 = forest.open(tree1_root, key1)?;
    assert!(
        proof1.verify_membership(&key1, &value1, &tree1_root),
        "Tree 1 should verify key1"
    );

    let proof2 = forest.open(tree1_root, key2)?;
    assert!(
        proof2.verify_membership(&key2, &value2, &tree1_root),
        "Tree 1 should verify key2"
    );

    // Verify tree1 does NOT contain keys from tree2
    let proof_key3_in_tree1 = forest.open(tree1_root, key3)?;
    assert!(
        !proof_key3_in_tree1.verify_membership(&key3, &value3, &tree1_root),
        "Tree 1 should not verify key3 with value3"
    );

    // Verify we can open and verify proofs from tree2
    let proof3 = forest.open(tree2_root, key3)?;
    assert!(
        proof3.verify_membership(&key3, &value3, &tree2_root),
        "Tree 2 should verify key3"
    );

    let proof4 = forest.open(tree2_root, key4)?;
    assert!(
        proof4.verify_membership(&key4, &value4, &tree2_root),
        "Tree 2 should verify key4"
    );

    // Verify tree2 does NOT contain keys from tree1
    let proof_key1_in_tree2 = forest.open(tree2_root, key1)?;
    assert!(
        !proof_key1_in_tree2.verify_membership(&key1, &value1, &tree2_root),
        "Tree 2 should not verify key1 with value1"
    );

    Ok(())
}
