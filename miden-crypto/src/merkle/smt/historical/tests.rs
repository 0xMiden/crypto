use super::*;
use crate::merkle::Smt;

#[derive(Debug)]
struct TestKV {
    key: Word,
    value: Word,
}

impl TestKV {
    fn new(n: u8) -> Self {
        let key = Rpo256::hash([n, 0, 0, 0].as_slice());
        let value = Rpo256::hash([n, n, 0, 0].as_slice());
        dbg!(TestKV { key, value })
    }
    fn tup(self) -> (Word, Word) {
        let Self { key, value } = self;
        (key, value)
    }
}

// Create a mock SMT with some initial data
fn create_mock_smt() -> Smt {
    let mut smt = Smt::new();

    // Insert some initial values
    for i in 1..=5 {
        let TestKV { key, value } = TestKV::new(i);
        smt.insert(key, value).unwrap();
    }

    smt
}

use std::dbg;

// Create test mutation sets
fn create_mutation_sets(
    smt: &Smt,
) -> (
    MutationSet<SMT_DEPTH, Word, Word>,
    MutationSet<SMT_DEPTH, Word, Word>,
    MutationSet<SMT_DEPTH, Word, Word>,
) {
    // First mutation set: Update existing keys and add new ones
    let smt0 = smt.clone();
    let _old_root1 = dbg!(smt0.root());

    let TestKV { key: key6, value: value6 } = TestKV::new(6);
    let (key2, value2_new) = (TestKV::new(2).key, Rpo256::hash(&[2u8, 20, 0, 0]));

    let mutations1 = smt0.compute_mutations(vec![(key6, value6), (key2, value2_new)]).unwrap();

    assert_eq!(mutations1.old_root, smt.root());

    // Apply mutations to get SMT after first mutations
    let mut smt1 = smt0.clone();
    smt1.apply_mutations(mutations1.clone()).unwrap();
    assert_eq!(mutations1.new_root, smt1.root());

    // Second mutation set: Remove a key (set to empty) and add another
    let kv7 = TestKV::new(7);
    let key3 = TestKV::new(3).key;

    let mutations2 = smt1.compute_mutations(vec![kv7.tup(), (key3, EMPTY_WORD)]).unwrap();

    // Apply mutations to get SMT after second mutations
    let mut smt2 = smt1.clone();
    smt2.apply_mutations(mutations2.clone()).unwrap();

    // Third mutation set: Multiple updates
    let (key8, value8) = TestKV::new(8).tup();
    let (key1, value1_new) = (TestKV::new(1).key, Rpo256::hash(&[1u8, 100, 0, 0]));
    let (key4, value4_new) = (TestKV::new(4).key, Rpo256::hash(&[4u8, 44, 0, 0]));

    let mutations3 = smt2
        .compute_mutations(vec![(key8, value8), (key1, value1_new), (key4, value4_new)])
        .unwrap();

    let mut smt3 = smt2.clone();
    smt3.apply_mutations(mutations3.clone()).unwrap();

    // validate coherence
    assert_eq!(smt.root(), mutations1.old_root());
    assert_eq!(mutations1.root(), mutations2.old_root());
    assert_eq!(mutations2.root(), mutations3.old_root());

    assert_ne!(mutations3.root(), mutations1.old_root());
    assert_ne!(mutations3.root(), mutations2.old_root());
    assert_ne!(mutations3.root(), mutations1.root());
    assert_ne!(mutations3.root(), mutations2.root());

    assert_eq!(mutations1.root(), smt1.root());
    assert_eq!(mutations2.root(), smt2.root());
    assert_eq!(mutations3.root(), smt3.root());

    assert_eq!(mutations1.old_root(), smt0.root());
    assert_eq!(mutations2.old_root(), smt1.root());
    assert_eq!(mutations3.old_root(), smt2.root());

    assert_ne!(smt0.root(), smt1.root());
    assert_ne!(smt1.root(), smt2.root());
    assert_ne!(smt2.root(), smt3.root());
    assert_ne!(smt0.root(), smt3.root());
    (mutations1, mutations2, mutations3)
}

#[test]
fn test_overlay_creation_and_inversion() {
    let smt = create_mock_smt();
    dbg!(smt.root());
    let (mutations1, ..) = create_mutation_sets(&smt);

    assert_eq!(mutations1.old_root, smt.root());

    assert_ne!(mutations1.old_root, mutations1.new_root);

    // Apply mutations to get the new state
    let mut smt_after = smt.clone();
    smt_after.apply_mutations(mutations1.clone()).unwrap();

    // Test creating an inverted overlay
    let overlay = Overlay::walkback(&smt_after, &mutations1).unwrap();

    // Verify that old and new roots are swapped
    assert_eq!(overlay.old_root(), mutations1.root());
    assert_eq!(overlay.root(), mutations1.old_root());
}

#[test]
fn test_historical_view_cache() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, _mutations3) = create_mutation_sets(&base_smt);

    let root0 = base_smt.root();

    // Apply mutations to get SMT states at each point
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    assert_ne!(root0, smt_after_1.root());

    let mut final_smt = smt_after_1.clone();
    final_smt.apply_mutations(mutations2.clone()).unwrap();

    assert_ne!(smt_after_1.root(), final_smt.root());
    assert_ne!(root0, final_smt.root());

    // Create historical SMT with overlays
    let mut smt_with_overlays = SmtWithOverlays::new(base_smt.clone(), 100);

    // but we need to add them in the block order
    smt_with_overlays.apply_mutations(mutations1).unwrap();
    smt_with_overlays.apply_mutations(mutations2).unwrap();

    assert_eq!(smt_with_overlays.root(), final_smt.root());

    // Get historical view at block 97 (3 overlays back)
    let historical_view = smt_with_overlays.historical_view(98).unwrap();

    // Test that cache is being used by checking same node multiple times
    let test_key = TestKV::new(1).key;
    let leaf_index = SmtWithOverlays::key_to_leaf_index(&test_key);
    let node_index = NodeIndex::from(leaf_index).parent();

    // First access should populate cache
    let hash1 = historical_view.get_value(&test_key);

    let hash2 = base_smt.get_value(&test_key);
    assert_eq!(hash1, hash2);

    // Note: There is no cache for this overlay/block_num since compared to the latest
    // there was no "poisioning" for the particluar node_index aka no change
    // and hence we can re-use the entry from the `latest` `Smt`.

    let base_root = base_smt.root();
    let historical_root = historical_view.root();
    assert_eq!(
        historical_root, base_root,
        "Historical root at block 97 should match base SMT root"
    );
}

#[test]
fn opening_works() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, _) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    // Create historical SMT
    let mut smt_with_overlays = SmtWithOverlays::new(base_smt.clone(), 100);

    smt_with_overlays.apply_mutations(mutations1.clone()).unwrap();
    smt_with_overlays.apply_mutations(mutations2.clone()).unwrap();

    let test_key = mutations1.new_pairs().iter().next().unwrap().0;
    let proof_vanilla = smt_after_1.open(&test_key);
    let view99 = smt_with_overlays.historical_view(99).unwrap();
    let proof_historic = view99.open(&test_key);
    assert_eq!(proof_vanilla, proof_historic);

    let test_key = mutations2.new_pairs().iter().last().unwrap().0;
    let proof_vanilla = smt_after_2.open(&test_key);
    let current = smt_with_overlays.open(&test_key);
    let pseudo_view = smt_with_overlays.historical_view(100).unwrap();
    let psuedo_historic = pseudo_view.open(&test_key);
    assert_eq!(psuedo_historic, current);
    assert_eq!(proof_vanilla, psuedo_historic);
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
    let mut smt_with_overlays = SmtWithOverlays::new(base_smt.clone(), 100);

    smt_with_overlays.apply_mutations(mutations1).unwrap();
    smt_with_overlays.apply_mutations(mutations2).unwrap();

    // Test opening for same keys at different historical points
    let test_keys =
        vec![TestKV::new(1).key, TestKV::new(2).key, TestKV::new(3).key, TestKV::new(6).key];

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

    // Apply mutations to get SMT states at each point
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    let mut final_smt = smt_after_2.clone();
    final_smt.apply_mutations(mutations3.clone()).unwrap();

    // Setup historical SMT
    let mut smt_with_overlays = SmtWithOverlays::new(base_smt.clone(), 100);

    smt_with_overlays.apply_mutations(mutations1).unwrap();
    smt_with_overlays.apply_mutations(mutations2).unwrap();
    smt_with_overlays.apply_mutations(mutations3).unwrap();

    // Test getting values at different historical points
    let key2 = TestKV::new(2).key;

    // At block 100 (current), key2 should have updated value from mutations1
    let view_100 = smt_with_overlays.historical_view(100).unwrap();
    let value_100 = view_100.get_value(&key2);
    assert_eq!(
        value_100,
        final_smt.get_value(&key2),
        "Value at block 100 should match final SMT"
    );

    // At block 97 (3 overlays back = base state), key2 should have original value
    let view_97 = smt_with_overlays.historical_view(97).unwrap();
    let value_97 = view_97.get_value(&key2);
    assert_eq!(value_97, base_smt.get_value(&key2), "Value at block 97 should match base SMT");

    // Also test a key that was added in mutations1 (key6)
    let key6 = TestKV::new(6).key;
    let view_100_key6 = view_100.get_value(&key6);
    let view_97_key6 = view_97.get_value(&key6);
    assert_eq!(view_100_key6, TestKV::new(6).value, "Key6 should exist at block 100");
    assert_eq!(view_97_key6, EMPTY_WORD, "Key6 should not exist at block 97");
}

#[test]
fn test_overlay_cleanup() {
    let smt = create_mock_smt();
    let mut smt_with_overlays = SmtWithOverlays::new(smt.clone(), 100);

    // Add more than MAX_OVERLAYS overlays
    for _i in 0..SmtWithOverlays::MAX_OVERLAYS * 2 {
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

#[test]
fn test_overlay_idx_latest() {
    // When requested == latest, should return Latest
    assert_eq!(SmtWithOverlays::overlay_idx(100, 100), HistoricalOffset::Latest);
    assert_eq!(SmtWithOverlays::overlay_idx(0, 0), HistoricalOffset::Latest);
    assert_eq!(SmtWithOverlays::overlay_idx(42, 42), HistoricalOffset::Latest);
}

#[test]
fn test_overlay_idx_recent() {
    // When difference is 1-32, should return OverlayIdx
    assert_eq!(SmtWithOverlays::overlay_idx(100, 99), HistoricalOffset::OverlayIdx(0));
    assert_eq!(SmtWithOverlays::overlay_idx(100, 98), HistoricalOffset::OverlayIdx(1));
    assert_eq!(SmtWithOverlays::overlay_idx(100, 68), HistoricalOffset::OverlayIdx(31));
    assert_eq!(SmtWithOverlays::overlay_idx(32, 0), HistoricalOffset::OverlayIdx(31));
}

#[test]
fn test_overlay_idx_too_ancient() {
    // When difference is >= 33, should return TooAncient
    assert_eq!(SmtWithOverlays::overlay_idx(100, 67), HistoricalOffset::TooAncient);
    assert_eq!(SmtWithOverlays::overlay_idx(33, 0), HistoricalOffset::TooAncient);
    assert_eq!(SmtWithOverlays::overlay_idx(1000, 900), HistoricalOffset::TooAncient);
}

#[test]
fn test_overlay_idx_future() {
    // When requested > latest (future block), should return TooAncient
    assert_eq!(SmtWithOverlays::overlay_idx(100, 101), HistoricalOffset::FutureBlock);
    assert_eq!(SmtWithOverlays::overlay_idx(0, 1), HistoricalOffset::FutureBlock);
    assert_eq!(SmtWithOverlays::overlay_idx(50, 100), HistoricalOffset::FutureBlock);
}

#[test]
fn test_overlay_idx_edge_cases() {
    // Edge case: exactly 32 blocks ago
    assert_eq!(SmtWithOverlays::overlay_idx(32, 0), HistoricalOffset::OverlayIdx(31));

    // Edge case: exactly 33 blocks ago (too ancient)
    assert_eq!(SmtWithOverlays::overlay_idx(33, 0), HistoricalOffset::TooAncient);

    // Edge case: small numbers
    assert_eq!(SmtWithOverlays::overlay_idx(1, 0), HistoricalOffset::OverlayIdx(0));
    assert_eq!(SmtWithOverlays::overlay_idx(2, 0), HistoricalOffset::OverlayIdx(1));
}
