use super::*;
use crate::hash::rpo::Rpo256;

// Helper to construct key value pairs
#[derive(Debug)]
struct TestKV {
    key: Word,
    value: Word,
}

impl TestKV {
    fn new(n: u8) -> Self {
        let key = Rpo256::hash([n, 0, 0, 0].as_slice());
        let value = Rpo256::hash([n, n, 0, 0].as_slice());
        TestKV { key, value }
    }
    fn tup(self) -> (Word, Word) {
        let Self { key, value } = self;
        (key, value)
    }
    fn with_value(self, value: &[u8]) -> Self {
        Self {
            key: self.key,
            value: Rpo256::hash(value),
        }
    }
    fn empty(self) -> Self {
        Self { key: self.key, value: EMPTY_WORD }
    }
}

// Create a mock SMT with some initial data
fn create_mock_smt() -> Smt {
    let mut smt = Smt::new();

    // Insert some initial values
    for i in 1..=3 {
        let TestKV { key, value } = TestKV::new(i);
        smt.insert(key, value).unwrap();
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
    let smt0 = smt.clone();
    let _old_root1 = smt0.root();

    let kv6 = TestKV::new(6);
    let kv2 = TestKV::new(2).with_value(&[2u8, 20]);

    let mutations1 = smt0.compute_mutations(vec![kv6.tup(), kv2.tup()]).unwrap();

    assert_eq!(mutations1.old_root(), smt.root());

    // Apply mutations to get SMT after first mutations
    let mut smt1 = smt0.clone();
    smt1.apply_mutations(mutations1.clone()).unwrap();
    assert_eq!(mutations1.root(), smt1.root());

    // Second mutation set: Remove a key (set to empty) and add another
    let kv7 = TestKV::new(7);
    let kv3 = TestKV::new(3).empty();

    let mutations2 = smt1.compute_mutations(vec![kv7.tup(), kv3.tup()]).unwrap();

    // Apply mutations to get SMT after second mutations
    let mut smt2 = smt1.clone();
    smt2.apply_mutations(mutations2.clone()).unwrap();

    // Third mutation set: Multiple updates
    let kv8 = TestKV::new(3).with_value(&[99u8, 128]);
    let kv1 = TestKV::new(1).with_value(&[1u8, 100]);
    let kv4 = TestKV::new(4).with_value(&[4u8, 44]);

    let mutations3 = smt2.compute_mutations(vec![kv8.tup(), kv1.tup(), kv4.tup()]).unwrap();

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
fn test_reversion_mutation_sets() {
    let smt = create_mock_smt();
    let (mutations1, ..) = create_mutation_sets(&smt);

    assert_eq!(mutations1.old_root(), smt.root());
    assert_ne!(mutations1.old_root(), mutations1.root());

    // Apply mutations to get the new state
    let mut smt_after = smt.clone();
    smt_after.apply_mutations(mutations1.clone()).unwrap();

    // The reversion mutation set should be able to restore the original state
    let mut smt_with_history = SmtWithHistory::new(smt.clone());
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();

    // Check that we have one reversion stored
    assert_eq!(smt_with_history.reversions.len(), 1);

    // The reversion should be able to restore the original root when applied
    let reversion = &smt_with_history.reversions[0];
    assert_eq!(reversion.old_root(), smt_after.root());
    assert_eq!(reversion.root(), smt.root());
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
    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());

    // but we need to add them in the block order
    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();

    assert_eq!(smt_with_history.root(), final_smt.root());

    // Get historical view at 2 overlays back (base state)
    let historical_view = smt_with_history.historical_view(2).unwrap();

    // Test that cache is being used by checking same node multiple times
    let test_key = TestKV::new(1).key;
    let _leaf_index = SmtWithHistory::key_to_leaf_index(&test_key);

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
        "Historical root at 2 overlays back should match base SMT root"
    );
}

#[test]
fn opening_works_no_mutations() {
    let base_smt = create_mock_smt();
    let (mutations1, ..) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    let test_key = TestKV::new(1).key;
    let base_proof = base_smt.open(&test_key);
    let htv = smt_with_history.historical_view(0).unwrap();
    let historic_proof = htv.open(&test_key);
    assert_eq!(base_smt.root(), htv.root());
    assert_eq!(base_proof, historic_proof);
}

#[test]
fn opening_works_post_1_mutations() {
    let base_smt = create_mock_smt();
    let (mutations1, ..) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();

    let test_key = TestKV::new(3).key; // doesn't exist in base, so empty key
    let base_proof = base_smt.open(&test_key);

    let htv = smt_with_history.historical_view(1).unwrap();
    let historic_proof = htv.open(&test_key);

    // historic
    let leaf = htv.get_leaf(&test_key);
    let xxx = {
        let leaf_idx = leaf.index();
        leaf_idx
            .index
            .proof_indices()
            .map(|haxx0r_idx| (haxx0r_idx, htv.get_node_hash(haxx0r_idx)))
    };

    let vanilla = {
        let index = NodeIndex::from(Smt::key_to_leaf_index(&test_key));
        index
            .proof_indices()
            .map(|vanilla_index| (vanilla_index, base_smt.get_node_hash(vanilla_index)))
    };

    vanilla
        .zip(xxx)
        .enumerate()
        .for_each(|(i, ((vanilla_idx, vanilla), (haxx_idx, haxx)))| {
            assert_eq!(vanilla_idx, haxx_idx);
            assert_eq!(
                vanilla, haxx,
                "iterator item {i} does not equality: {vanilla:?} != {haxx:?} when it should"
            )
        });

    assert_eq!(base_smt.root(), htv.root());
    assert_eq!(base_proof, historic_proof);
}

#[test]
fn opening_works_post_2_mutations() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, _mutations3) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();
    smt_with_history.apply_mutations(mutations2.clone()).unwrap();

    let test_key = TestKV::new(3).key; // key 3 exists in base
    let base_proof = base_smt.open(&test_key);
    let htv = smt_with_history.historical_view(2).unwrap();
    let historic_proof = htv.open(&test_key);
    assert_eq!(base_smt.root(), htv.root());
    assert_eq!(base_proof, historic_proof);
}

#[test]
fn opening_works_post_3_mutations() {
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, mutations3) = create_mutation_sets(&base_smt);

    // Create intermediate SMT states
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    let mut smt_after_3 = smt_after_2.clone();
    smt_after_3.apply_mutations(mutations3.clone()).unwrap();

    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();
    smt_with_history.apply_mutations(mutations2.clone()).unwrap();
    smt_with_history.apply_mutations(mutations3.clone()).unwrap();

    let test_key = TestKV::new(3).key; // key 3 exists in base
    let base_proof = base_smt.open(&test_key);
    let htv = smt_with_history.historical_view(3).unwrap();
    let historic_proof = htv.open(&test_key);
    assert_eq!(base_smt.root(), htv.root());
    assert_eq!(base_proof, historic_proof);
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
    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());

    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();

    // Test opening for same keys at different historical points
    let test_keys =
        vec![TestKV::new(1).key, TestKV::new(2).key, TestKV::new(3).key, TestKV::new(6).key];

    for key in test_keys {
        // Compare at current state (0 overlays back)
        let current_view = smt_with_history.historical_view(0).unwrap();
        let current_proof = current_view.open(&key);
        let vanilla_proof = smt_after_2.open(&key);

        assert_eq!(current_proof.leaf(), vanilla_proof.leaf());
        assert_eq!(current_proof.path(), vanilla_proof.path());

        // Compare at 1 overlay back (after first mutation)
        let historical_view_1 = smt_with_history.historical_view(1).unwrap();
        let historical_proof_1 = historical_view_1.open(&key);
        let vanilla_proof_1 = smt_after_1.open(&key);

        assert_eq!(historical_proof_1.leaf(), vanilla_proof_1.leaf());
        assert_eq!(historical_proof_1.path(), vanilla_proof_1.path());

        // Compare at 2 overlays back (base state)
        let historical_view_2 = smt_with_history.historical_view(2).unwrap();
        let historical_proof_2 = historical_view_2.open(&key);
        let vanilla_proof_2 = base_smt.open(&key);

        assert_eq!(historical_proof_2.leaf(), vanilla_proof_2.leaf());
        assert_eq!(historical_proof_2.path(), vanilla_proof_2.path());
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
    let mut smt_with_history = SmtWithHistory::new(base_smt.clone());

    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();
    smt_with_history.apply_mutations(mutations3).unwrap();

    // Test getting values at different historical points
    let key2 = TestKV::new(2).key;

    // At current state (0 overlays back), key2 should have updated value from mutations1
    let view_current = smt_with_history.historical_view(0).unwrap();
    let value_current = view_current.get_value(&key2);
    assert_eq!(
        value_current,
        final_smt.get_value(&key2),
        "Value at current state should match final SMT"
    );

    // At 3 overlays back (base state), key2 should have original value
    let view_base = smt_with_history.historical_view(3).unwrap();
    let value_base = view_base.get_value(&key2);
    assert_eq!(
        value_base,
        base_smt.get_value(&key2),
        "Value at base state should match base SMT"
    );

    // Also test a key that was added in mutations1 (key6)
    let key6 = TestKV::new(6).key;
    let view_current_key6 = view_current.get_value(&key6);
    let view_base_key6 = view_base.get_value(&key6);
    assert_eq!(view_current_key6, TestKV::new(6).value, "Key6 should exist at current state");
    assert_eq!(view_base_key6, EMPTY_WORD, "Key6 should not exist at base state");
}

#[test]
fn test_reversion_cleanup() {
    let smt = create_mock_smt();
    let mut smt_with_history = SmtWithHistory::new(smt.clone());

    // Add more than MAX_OVERLAYS reversions by applying mutations
    for i in 0..SmtWithHistory::MAX_HISTORY * 2 {
        // Create a unique mutation for each iteration
        let kv = TestKV::new((i % 255) as u8);
        let mutations = smt_with_history.latest.compute_mutations(vec![kv.tup()]).unwrap();
        smt_with_history.apply_mutations(mutations).unwrap();
    }

    // Verify that only MAX_OVERLAYS are kept
    assert_eq!(smt_with_history.reversions.len(), SmtWithHistory::MAX_HISTORY);
}

#[test]
fn test_historical_offset_latest() {
    // When offset is 0, should return Latest
    assert_eq!(SmtWithHistory::historical_offset(0), HistoricalOffset::Latest);
}

#[test]
fn test_historical_offset_recent() {
    // When offset is 1-32, should return ReversionsIdx
    assert_eq!(SmtWithHistory::historical_offset(1), HistoricalOffset::ReversionsIdx(0));
    assert_eq!(SmtWithHistory::historical_offset(2), HistoricalOffset::ReversionsIdx(1));
    assert_eq!(SmtWithHistory::historical_offset(32), HistoricalOffset::ReversionsIdx(31));
}

#[test]
fn test_historical_offset_too_ancient() {
    // When offset is > 32, should return TooAncient
    assert_eq!(SmtWithHistory::historical_offset(33), HistoricalOffset::TooAncient);
    assert_eq!(SmtWithHistory::historical_offset(100), HistoricalOffset::TooAncient);
}

#[test]
fn test_historical_offset_edge_cases() {
    // Edge case: exactly 32 blocks ago
    assert_eq!(SmtWithHistory::historical_offset(32), HistoricalOffset::ReversionsIdx(31));

    // Edge case: exactly 33 blocks ago (too ancient)
    assert_eq!(SmtWithHistory::historical_offset(33), HistoricalOffset::TooAncient);

    // Edge case: small numbers
    assert_eq!(SmtWithHistory::historical_offset(1), HistoricalOffset::ReversionsIdx(0));
    assert_eq!(SmtWithHistory::historical_offset(2), HistoricalOffset::ReversionsIdx(1));
}
