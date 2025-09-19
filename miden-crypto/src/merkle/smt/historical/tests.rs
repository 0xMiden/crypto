use super::*;
use crate::merkle::{Smt, SmtLeaf};

// Helper function to create a test key-value pair
fn test_pair(n: u8) -> (Word, Word) {
    let key = Rpo256::hash([n, 0, 0, 0].as_slice());
    let value = Rpo256::hash([n, n, 0, 0].as_slice());
    (key, value)
}

// Create a mock SMT with some initial data
fn create_mock_smt() -> Smt {
    let mut smt = Smt::new();

    // Insert some initial values
    for i in 1..=5 {
        let (key, value) = test_pair(i);
        smt.insert(key, value);
    }

    smt
}

// Create test mutation sets
fn create_mutation_sets(
    smt: &Smt,
) -> (
    MutationSet<SMT_DEPTH, Word, Word>,
    MutationSet<SMT_DEPTH, Word, Word>,
    MutationSet<SMT_DEPTH, Word, Word>,
) {
    // First mutation set: Update existing keys and add new ones
    let mut smt1 = smt.clone();
    let old_root1 = smt1.root();

    let (key6, value6) = test_pair(6);
    let (key2, value2_new) =
        (test_pair(2).0, Rpo256::new([2.into(), 20.into(), 0.into(), 0.into()]).into());

    smt1.insert(key6, value6);
    smt1.insert(key2, value2_new);

    let mutations1 = smt1.compute_mutations(vec![(key6, value6), (key2, value2_new)]).unwrap();

    // Second mutation set: Remove a key (set to empty) and add another
    let mut smt2 = smt1.clone();
    let old_root2 = smt2.root();

    let (key7, value7) = test_pair(7);
    let (key3, _) = test_pair(3);

    smt2.insert(key7, value7);
    smt2.insert(key3, EMPTY_WORD); // Remove key3

    let mutations2 = smt2.compute_mutations(vec![(key7, value7), (key3, EMPTY_WORD)]).unwrap();

    // Third mutation set: Multiple updates
    let mut smt3 = smt2.clone();
    let old_root3 = smt3.root();

    let (key8, value8) = test_pair(8);
    let (key1, value1_new) = (
        test_pair(1).0,
        RpoDigest::new([1.into(), 100.into(), 0.into(), 0.into()]).into(),
    );
    let (key4, value4_new) = (
        test_pair(4).0,
        RpoDigest::new([4.into(), 400.into(), 0.into(), 0.into()]).into(),
    );

    smt3.insert(key8, value8);
    smt3.insert(key1, value1_new);
    smt3.insert(key4, value4_new);

    let mutations3 = smt3
        .compute_mutations(vec![(key8, value8), (key1, value1_new), (key4, value4_new)])
        .unwrap();

    (mutations1, mutations2, mutations3)
}

#[test]
fn test_overlay_creation_and_inversion() {
    let smt = create_mock_smt();
    let (mutations1, ..) = create_mutation_sets(&smt);

    // Test creating an inverted overlay
    let overlay = Overlay::inverted(&smt, &mutations1).unwrap();

    // Verify that old and new roots are swapped
    assert_eq!(overlay.old_root(), mutations1.root());
    assert_eq!(overlay.root(), mutations1.old_root());
}

#[test]
fn test_historical_view_cache() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, mutations3) = create_mutation_sets(&base_smt);

    // Apply mutations to get final SMT state
    let mut final_smt = base_smt.clone();
    final_smt.apply_mutations(mutations1.clone()).unwrap();
    final_smt.apply_mutations(mutations2.clone()).unwrap();
    final_smt.apply_mutations(mutations3.clone()).unwrap();

    // Create historical SMT with overlays
    let mut smt_with_overlays = SmtWithOverlays::new(final_smt.clone(), 100);

    // Add overlays (in reverse order since they represent going backwards)
    let overlay3 = Overlay::inverted(&final_smt, &mutations3).unwrap();
    let mut smt_after_2 = final_smt.clone();
    smt_after_2.apply_mutations(overlay3.clone().into()).unwrap();

    let overlay2 = Overlay::inverted(&smt_after_2, &mutations2).unwrap();
    let mut smt_after_1 = smt_after_2.clone();
    smt_after_1.apply_mutations(overlay2.clone().into()).unwrap();

    let overlay1 = Overlay::inverted(&smt_after_1, &mutations1).unwrap();

    smt_with_overlays.add_overlay(overlay3);
    smt_with_overlays.add_overlay(overlay2);
    smt_with_overlays.add_overlay(overlay1);

    // Get historical view at block 97 (3 overlays back)
    let historical_view = smt_with_overlays.historical_view(97).unwrap();

    // Test that cache is being used by checking same node multiple times
    let test_key = test_pair(1).0;
    let leaf_index = SmtWithOverlays::key_to_leaf_index(&test_key);
    let node_index = NodeIndex::from(leaf_index).parent();

    // First access should populate cache
    let hash1 = historical_view.get_node_hash(node_index);

    // Second access should use cache
    let hash2 = historical_view.get_node_hash(node_index);

    assert_eq!(hash1, hash2);

    // Verify cache contains the entry
    assert!(historical_view.cache.borrow().get(&97).is_some());
}

#[test]
fn test_opening_comparison_with_vanilla_smt() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, _) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    // Create historical SMT
    let mut smt_with_overlays = SmtWithOverlays::new(smt_after_2.clone(), 100);

    // Add overlays for historical access
    let overlay2 = Overlay::inverted(&smt_after_2, &mutations2).unwrap();
    let overlay1 = Overlay::inverted(&smt_after_1, &mutations1).unwrap();

    smt_with_overlays.add_overlay(overlay2);
    smt_with_overlays.add_overlay(overlay1);

    // Test opening for same keys at different historical points
    let test_keys = vec![test_pair(1).0, test_pair(2).0, test_pair(3).0, test_pair(6).0];

    for key in test_keys {
        // Compare at block 100 (current state)
        let current_view = smt_with_overlays.historical_view(100).unwrap();
        let current_proof = current_view.open(&key);
        let vanilla_proof = smt_after_2.open(&key);

        assert_eq!(current_proof.leaf(), vanilla_proof.leaf());
        assert_eq!(current_proof.path(), vanilla_proof.path());

        // Compare at block 99 (after first mutation)
        let historical_view_99 = smt_with_overlays.historical_view(99).unwrap();
        let historical_proof_99 = historical_view_99.open(&key);
        let vanilla_proof_99 = smt_after_1.open(&key);

        assert_eq!(historical_proof_99.leaf(), vanilla_proof_99.leaf());
        assert_eq!(historical_proof_99.path(), vanilla_proof_99.path());

        // Compare at block 98 (base state)
        let historical_view_98 = smt_with_overlays.historical_view(98).unwrap();
        let historical_proof_98 = historical_view_98.open(&key);
        let vanilla_proof_98 = base_smt.open(&key);

        assert_eq!(historical_proof_98.leaf(), vanilla_proof_98.leaf());
        assert_eq!(historical_proof_98.path(), vanilla_proof_98.path());
    }
}

#[test]
fn test_get_value_across_overlays() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, mutations3) = create_mutation_sets(&base_smt);

    // Apply all mutations
    let mut final_smt = base_smt.clone();
    final_smt.apply_mutations(mutations1.clone()).unwrap();
    final_smt.apply_mutations(mutations2.clone()).unwrap();
    final_smt.apply_mutations(mutations3.clone()).unwrap();

    // Setup historical SMT
    let mut smt_with_overlays = SmtWithOverlays::new(final_smt.clone(), 100);

    let overlay3 = Overlay::inverted(&final_smt, &mutations3).unwrap();
    let overlay2_smt = {
        let mut s = final_smt.clone();
        s.apply_mutations(overlay3.clone().into()).unwrap();
        s
    };
    let overlay2 = Overlay::inverted(&overlay2_smt, &mutations2).unwrap();
    let overlay1_smt = {
        let mut s = overlay2_smt.clone();
        s.apply_mutations(overlay2.clone().into()).unwrap();
        s
    };
    let overlay1 = Overlay::inverted(&overlay1_smt, &mutations1).unwrap();

    smt_with_overlays.add_overlay(overlay3);
    smt_with_overlays.add_overlay(overlay2);
    smt_with_overlays.add_overlay(overlay1);

    // Test getting values at different historical points
    let key2 = test_pair(2).0;

    // At block 100 (current), key2 should have updated value
    let view_100 = smt_with_overlays.historical_view(100).unwrap();
    let value_100 = view_100.get_value(&key2);
    assert_eq!(value_100, final_smt.get_value(&key2));

    // At block 98 (base), key2 should have original value
    let view_98 = smt_with_overlays.historical_view(98).unwrap();
    let value_98 = view_98.get_value(&key2);
    assert_eq!(value_98, base_smt.get_value(&key2));
}

#[test]
fn test_overlay_cleanup() {
    let smt = create_mock_smt();
    let mut smt_with_overlays = SmtWithOverlays::new(smt.clone(), 100);

    // Add more than MAX_OVERLAYS overlays
    for i in 0..40 {
        let overlay = Overlay {
            old_root: EMPTY_WORD,
            new_root: EMPTY_WORD,
            mutated: HashMap::new(),
            poisoned_tree_leaves: Vec::new(),
        };
        smt_with_overlays.add_overlay(overlay);
    }

    // Verify that only MAX_OVERLAYS are kept
    assert_eq!(smt_with_overlays.overlays.len(), SmtWithOverlays::MAX_OVERLAYS);
}
