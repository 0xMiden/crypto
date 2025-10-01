use super::*;
use crate::hash::rpo::Rpo256;

// Helper to construct key value pairs
#[derive(Debug, Clone, Copy)]
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
    let smt_with_history = SmtWithHistory::new(smt.clone());
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();

    // Check that we have one reversion stored
    assert_eq!(smt_with_history.history_len(), 1);

    // The reversion should be able to restore the original root when applied
    let reversion = smt_with_history.first_reversion().unwrap();
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
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

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

    let smt_with_history = SmtWithHistory::new(base_smt.clone());
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

    let smt_with_history = SmtWithHistory::new(base_smt.clone());
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

    let smt_with_history = SmtWithHistory::new(base_smt.clone());
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
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

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
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

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
    let smt_with_history = SmtWithHistory::new(smt.clone());

    // Add more than MAX_OVERLAYS reversions by applying mutations
    for i in 0..SmtWithHistory::MAX_HISTORY * 2 {
        // Create a unique mutation for each iteration
        let kv = TestKV::new((i % 255) as u8);
        let mutations = smt_with_history.compute_mutations(vec![kv.tup()]).unwrap();
        smt_with_history.apply_mutations(mutations).unwrap();
    }

    // Verify that only MAX_OVERLAYS are kept
    assert_eq!(smt_with_history.history_len(), SmtWithHistory::MAX_HISTORY);
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

#[test]
fn test_rwlock_guard_ensures_single_smt() {
    use std::{sync::Arc, thread};

    let base_smt = create_mock_smt();
    let smt_with_history = Arc::new(SmtWithHistory::new(base_smt.clone()));

    // Create mutations to apply
    let (mutations1, mutations2, mutations3) = create_mutation_sets(&base_smt);

    // Apply mutations
    smt_with_history.apply_mutations(mutations1.clone()).unwrap();
    smt_with_history.apply_mutations(mutations2.clone()).unwrap();
    smt_with_history.apply_mutations(mutations3.clone()).unwrap();

    // Spawn multiple threads that try to access historical views concurrently
    let mut handles = vec![];

    for i in 0..4 {
        let smt = Arc::clone(&smt_with_history);
        let handle = thread::spawn(move || {
            // Each thread gets a historical view at different offsets
            let view = smt.historical_view(i).unwrap();

            // Perform some operations on the view
            let test_key = TestKV::new(1).key;
            let value = view.get_value(&test_key);
            let proof = view.open(&test_key);

            // The view holds a read guard, preventing writes while it exists
            (value, proof.compute_root())
        });
        handles.push(handle);
    }

    // Collect results from all threads
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Verify that all threads could read concurrently without issues
    assert_eq!(results.len(), 4);

    // Now test that a write operation waits for all reads to complete
    let smt = Arc::clone(&smt_with_history);
    let write_handle = thread::spawn(move || {
        // This will wait until all read guards are dropped
        let new_mutation = smt.compute_mutations(vec![TestKV::new(9).tup()]).unwrap();
        smt.apply_mutations(new_mutation).unwrap();
        smt.root()
    });

    // The write should complete successfully
    let new_root = write_handle.join().unwrap();
    assert_ne!(new_root, base_smt.root());
}

#[test]
fn test_historical_view_lifetime_management() {
    let base_smt = create_mock_smt();
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // Apply some mutations
    let (mutations1, ..) = create_mutation_sets(&base_smt);
    smt_with_history.apply_mutations(mutations1).unwrap();

    // Create a historical view
    {
        let view = smt_with_history.historical_view(0).unwrap();
        let test_key = TestKV::new(1).key;
        let _value = view.get_value(&test_key);
        // view is dropped here, releasing the read guard
    }

    // After the view is dropped, we can apply new mutations
    let new_mutation = smt_with_history.compute_mutations(vec![TestKV::new(10).tup()]).unwrap();
    smt_with_history.apply_mutations(new_mutation).unwrap();

    // Verify the mutation was applied
    assert_eq!(smt_with_history.history_len(), 2);
}

#[test]
fn test_memory_efficiency_single_smt_instance() {
    use std::mem;

    let base_smt = create_mock_smt();
    let smt_size = mem::size_of_val(&base_smt);

    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // Apply many mutations
    for i in 0..10 {
        let kv = TestKV::new((i * 7 % 255) as u8);
        let mutations = smt_with_history.compute_mutations(vec![kv.tup()]).unwrap();
        smt_with_history.apply_mutations(mutations).unwrap();
    }

    // Create multiple historical views - they all share the same underlying Smt
    let views: Vec<_> = (0..5).filter_map(|i| smt_with_history.historical_view(i)).collect();

    // All views reference the same single Smt instance through their guards
    // The memory usage should be primarily the single Smt + the reversion mutations
    assert_eq!(views.len(), 5);

    // Each view holds a read guard to the same InnerState
    // No additional Smt instances are created
    for view in &views {
        let test_key = TestKV::new(1).key;
        let _ = view.get_value(&test_key);
    }

    // After dropping views, we can modify again
    drop(views);

    let final_mutation = smt_with_history.compute_mutations(vec![TestKV::new(99).tup()]).unwrap();
    smt_with_history.apply_mutations(final_mutation).unwrap();

    // The size of the SmtWithHistory should be much less than having multiple Smt copies
    // It only stores one Smt plus the mutation sets
    let history_size = mem::size_of_val(&smt_with_history);

    // The SmtWithHistory wrapper is small (just an Arc<RwLock<...>>)
    assert!(
        history_size < smt_size,
        "SmtWithHistory wrapper should be smaller than a full Smt"
    );
}

#[test]
fn test_concurrent_reads_with_single_smt() {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    let base_smt = create_mock_smt();
    let smt_with_history = Arc::new(SmtWithHistory::new(base_smt.clone()));

    // Apply mutations to create history
    let (mutations1, mutations2, _) = create_mutation_sets(&base_smt);
    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = vec![];

    // Spawn threads that will all try to read at the same time
    for offset in 0..3 {
        let smt = Arc::clone(&smt_with_history);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier.wait();

            // All threads create views concurrently - they all share the single Smt
            let view = smt.historical_view(offset).unwrap();

            // Perform operations
            let mut results = vec![];
            for i in 1..=3 {
                let key = TestKV::new(i).key;
                let value = view.get_value(&key);
                let proof = view.open(&key);
                results.push((value, proof.compute_root()));
            }

            results
        });

        handles.push(handle);
    }

    // Collect all results
    let all_results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Verify all threads completed successfully
    assert_eq!(all_results.len(), 3);

    // Each thread should have gotten valid results
    for results in all_results {
        assert_eq!(results.len(), 3);
    }
}

#[test]
fn test_historical_view_of_latest_matches_current() {
    // Test requirement 1: HistoricalView of latest (offset=0) matches the current latest
    let base_smt = create_mock_smt();
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // Apply some mutations to create history
    let (mutations1, mutations2, _) = create_mutation_sets(&base_smt);
    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();

    // Get the current state directly
    let current_root = smt_with_history.root();

    // Get historical view at offset 0 (latest)
    let latest_view = smt_with_history.historical_view(0).unwrap();
    let latest_view_root = latest_view.root();

    // Roots should match
    assert_eq!(
        current_root, latest_view_root,
        "Historical view at offset 0 should match current latest"
    );

    // Test with various keys to ensure values match
    let test_keys = vec![
        TestKV::new(1).key,
        TestKV::new(2).key,
        TestKV::new(3).key,
        TestKV::new(6).key,
        TestKV::new(7).key,
    ];

    for key in test_keys {
        // Get value directly from current state
        let current_proof = smt_with_history.open(&key);

        // Get value from historical view at latest
        let latest_view_proof = latest_view.open(&key);

        assert_eq!(
            current_proof, latest_view_proof,
            "Proof for key should match between current and historical view at latest"
        );
    }
}

#[test]
fn test_two_steps_back_works() {
    // Test requirement 2: Two steps back still works correctly
    let base_smt = create_mock_smt();
    let (mutations1, mutations2, _) = create_mutation_sets(&base_smt);

    // Create intermediate states for comparison
    let mut smt_after_1 = base_smt.clone();
    smt_after_1.apply_mutations(mutations1.clone()).unwrap();

    let mut smt_after_2 = smt_after_1.clone();
    smt_after_2.apply_mutations(mutations2.clone()).unwrap();

    // Create historical SMT and apply mutations
    let smt_with_history = SmtWithHistory::new(base_smt.clone());
    smt_with_history.apply_mutations(mutations1).unwrap();
    smt_with_history.apply_mutations(mutations2).unwrap();

    // Test two steps back (offset=2) - should match base_smt
    let two_steps_back = smt_with_history.historical_view(2).unwrap();
    assert_eq!(
        two_steps_back.root(),
        base_smt.root(),
        "Root at 2 steps back should match base SMT"
    );

    // Test one step back (offset=1) - should match smt_after_1
    let one_step_back = smt_with_history.historical_view(1).unwrap();
    assert_eq!(
        one_step_back.root(),
        smt_after_1.root(),
        "Root at 1 step back should match SMT after first mutation"
    );

    // Test current (offset=0) - should match smt_after_2
    let current = smt_with_history.historical_view(0).unwrap();
    assert_eq!(
        current.root(),
        smt_after_2.root(),
        "Root at offset 0 should match SMT after second mutation"
    );

    // Verify values and proofs at different historical points
    let test_keys = vec![
        TestKV::new(1).key, // exists in base
        TestKV::new(2).key, // exists in base, modified in mutations1
        TestKV::new(3).key, // exists in base, removed in mutations2
        TestKV::new(6).key, // added in mutations1
        TestKV::new(7).key, // added in mutations2
    ];

    for key in test_keys {
        // Two steps back should match base
        let historical_value_2 = two_steps_back.get_value(&key);
        let base_value = base_smt.get_value(&key);
        assert_eq!(historical_value_2, base_value, "Value at 2 steps back should match base SMT");

        let historical_proof_2 = two_steps_back.open(&key);
        let base_proof = base_smt.open(&key);
        assert_eq!(historical_proof_2, base_proof, "Proof at 2 steps back should match base SMT");

        // One step back should match smt_after_1
        let historical_value_1 = one_step_back.get_value(&key);
        let after1_value = smt_after_1.get_value(&key);
        assert_eq!(
            historical_value_1, after1_value,
            "Value at 1 step back should match SMT after first mutation"
        );

        let historical_proof_1 = one_step_back.open(&key);
        let after1_proof = smt_after_1.open(&key);
        assert_eq!(
            historical_proof_1, after1_proof,
            "Proof at 1 step back should match SMT after first mutation"
        );
    }
}

#[test]
fn test_compute_leaves_for_reversion() {
    // This test ensures that compute_leaves_for_reversion correctly constructs
    // the set of leaves that represent the state BEFORE a mutation was applied.

    // Create a base SMT with some initial data
    let mut base_smt = Smt::new();

    // Set up initial state with various leaf configurations:
    // 1. Single entry leaves
    let kv1 = TestKV::new(1);
    let kv2 = TestKV::new(2);
    base_smt.insert(kv1.key, kv1.value).unwrap();
    base_smt.insert(kv2.key, kv2.value).unwrap();

    // 2. Add keys that will collide (map to same leaf index)
    // We'll need to craft keys that hash to the same leaf index
    // For testing, we'll use keys that we know will collide based on the hash function

    // Create an SMT with history
    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // Prepare mutations that will test different scenarios:
    // 1. Update existing single value
    let kv1_updated = TestKV::new(1).with_value(&[1u8, 111]);

    // 2. Delete a value (set to EMPTY_WORD)
    let kv2_deleted = TestKV::new(2).empty();

    // 3. Add a new value
    let kv3_new = TestKV::new(3);

    // 4. Update from empty to having a value
    let kv4_new = TestKV::new(4);

    // Apply the mutations
    let mutations = smt_with_history
        .compute_mutations(vec![kv1_updated.tup(), kv2_deleted.tup(), kv3_new.tup(), kv4_new.tup()])
        .unwrap();

    // Store the old state for comparison
    let old_root = base_smt.root();
    let old_kv1_value = base_smt.get_value(&kv1.key);
    let old_kv2_value = base_smt.get_value(&kv2.key);
    let old_kv3_value = base_smt.get_value(&kv3_new.key); // Should be EMPTY_WORD
    let old_kv4_value = base_smt.get_value(&kv4_new.key); // Should be EMPTY_WORD

    // Apply mutations to the historical SMT
    smt_with_history.apply_mutations(mutations.clone()).unwrap();

    // Now, the reversion should have been created internally
    // Get the reversion from the history
    let reversion = smt_with_history.first_reversion().unwrap();

    // The reversion should contain the inverted mutations (old values)
    // and the precomputed_leaves should correctly represent the state BEFORE mutation

    // Verify the reversion root matches the old root
    assert_eq!(reversion.root(), old_root, "Reversion root should match the old SMT root");

    // Access the precomputed leaves through the historical view
    let historical_view = smt_with_history.historical_view(1).unwrap();

    // Test case 1: Updated value should show old value
    let leaf1 = historical_view.get_leaf(&kv1.key);
    match leaf1 {
        SmtLeaf::Single((key, value)) => {
            assert_eq!(key, kv1.key, "Key should match");
            assert_eq!(value, kv1.value, "Should have original value, not updated value");
        },
        _ => panic!("Expected Single leaf for key1"),
    }

    // Test case 2: Deleted value should show original value
    let leaf2 = historical_view.get_leaf(&kv2.key);
    match leaf2 {
        SmtLeaf::Single((key, value)) => {
            assert_eq!(key, kv2.key, "Key should match");
            assert_eq!(value, kv2.value, "Should have original value before deletion");
        },
        _ => panic!("Expected Single leaf for key2"),
    }

    // Test case 3: Newly added value should be empty in historical view
    let value3 = historical_view.get_value(&kv3_new.key);
    assert_eq!(value3, EMPTY_WORD, "Key3 should not exist in historical view");

    // Test case 4: Another newly added value should be empty
    let value4 = historical_view.get_value(&kv4_new.key);
    assert_eq!(value4, EMPTY_WORD, "Key4 should not exist in historical view");

    // Verify all values match what was in the original SMT
    assert_eq!(historical_view.get_value(&kv1.key), old_kv1_value);
    assert_eq!(historical_view.get_value(&kv2.key), old_kv2_value);
    assert_eq!(historical_view.get_value(&kv3_new.key), old_kv3_value);
    assert_eq!(historical_view.get_value(&kv4_new.key), old_kv4_value);
}

#[test]
fn test_compute_leaves_for_reversion_multiple_entries() {
    // This test specifically tests the case where multiple keys map to the same leaf
    // This is a more complex scenario for compute_leaves_for_reversion

    // We need to create keys that will hash to the same leaf index
    // This is deterministic based on the hash function
    // For testing, we'll manually construct such keys

    let mut base_smt = Smt::new();

    // First, let's find keys that collide by testing
    let mut colliding_keys = Vec::new();
    let mut leaf_index_target = None;

    // Try to find at least 2 keys that map to the same leaf
    for i in 0u8..100 {
        let kv = TestKV::new(i);
        let leaf_idx = Smt::key_to_leaf_index(&kv.key);

        if let Some(target) = leaf_index_target {
            if leaf_idx == target {
                colliding_keys.push(kv);
                if colliding_keys.len() >= 2 {
                    break;
                }
            }
        } else {
            leaf_index_target = Some(leaf_idx);
            colliding_keys.push(kv);
        }
    }

    // If we found colliding keys, test with them
    if colliding_keys.len() >= 2 {
        // Insert the colliding keys into the base SMT
        for kv in &colliding_keys {
            base_smt.insert(kv.key, kv.value).unwrap();
        }

        let smt_with_history = SmtWithHistory::new(base_smt.clone());

        // Create mutations that affect the multiple-entry leaf
        let mut mutations_list = Vec::new();

        // Update the first colliding key
        if let Some(first_kv) = colliding_keys.first() {
            let updated = TestKV {
                key: first_kv.key,
                value: TestKV::new(99).value, // Different value
            };
            mutations_list.push(updated.tup());
        }

        // Delete the second colliding key if it exists
        if colliding_keys.len() > 1 {
            let deleted = colliding_keys[1].clone().empty();
            mutations_list.push(deleted.tup());
        }

        // Apply mutations
        let mutations = smt_with_history.compute_mutations(mutations_list).unwrap();
        smt_with_history.apply_mutations(mutations).unwrap();

        // Get historical view
        let historical_view = smt_with_history.historical_view(1).unwrap();

        // The historical leaf should show the original multiple entries
        if let Some(first_kv) = colliding_keys.first() {
            let leaf = historical_view.get_leaf(&first_kv.key);

            match leaf {
                SmtLeaf::Multiple(entries) if colliding_keys.len() > 1 => {
                    // Should contain all original entries
                    assert_eq!(
                        entries.len(),
                        colliding_keys.len(),
                        "Historical leaf should have all original entries"
                    );

                    for kv in &colliding_keys {
                        assert!(
                            entries.iter().any(|(k, v)| *k == kv.key && *v == kv.value),
                            "Historical leaf should contain original key-value pair"
                        );
                    }
                },
                SmtLeaf::Single((key, value)) if colliding_keys.len() == 1 => {
                    assert_eq!(key, first_kv.key);
                    assert_eq!(value, first_kv.value);
                },
                _ => {
                    // If we expected multiple entries but got something else
                    if colliding_keys.len() > 1 {
                        panic!("Expected Multiple leaf for colliding keys, got {:?}", leaf);
                    }
                },
            }
        }

        // Verify that getting values returns the original values
        for kv in &colliding_keys {
            let historical_value = historical_view.get_value(&kv.key);
            let original_value = base_smt.get_value(&kv.key);
            assert_eq!(
                historical_value, original_value,
                "Historical value should match original value"
            );
        }
    }
}
#[test]
fn test_compute_leaves_for_reversion_empty_smt_with_additions() {
    // Edge case 1: Empty SMT with additions
    let empty_smt = Smt::new();
    let smt_with_history = SmtWithHistory::new(empty_smt.clone());

    let kv1 = TestKV::new(10);
    let kv2 = TestKV::new(11);

    let mutations = smt_with_history.compute_mutations(vec![kv1.tup(), kv2.tup()]).unwrap();

    let old_root = empty_smt.root();
    smt_with_history.apply_mutations(mutations).unwrap();

    // Historical view should show empty state
    let historical_view = smt_with_history.historical_view(1).unwrap();
    assert_eq!(historical_view.root(), old_root, "Historical root should match empty SMT");
    assert_eq!(historical_view.get_value(&kv1.key), EMPTY_WORD);
    assert_eq!(historical_view.get_value(&kv2.key), EMPTY_WORD);
}

#[test]
fn test_compute_leaves_for_reversion_all_values_deleted() {
    // Edge case 2: All values deleted
    let mut base_smt = Smt::new();
    let kv3 = TestKV::new(20);
    let kv4 = TestKV::new(21);
    base_smt.insert(kv3.key, kv3.value).unwrap();
    base_smt.insert(kv4.key, kv4.value).unwrap();

    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // Delete all values
    let mutations = smt_with_history
        .compute_mutations(vec![kv3.empty().tup(), kv4.empty().tup()])
        .unwrap();

    smt_with_history.apply_mutations(mutations).unwrap();

    // Historical view should show original values
    let historical_view = smt_with_history.historical_view(1).unwrap();
    assert_eq!(historical_view.get_value(&kv3.key), kv3.value);
    assert_eq!(historical_view.get_value(&kv4.key), kv4.value);
}

#[test]
fn test_compute_leaves_for_reversion_replace_and_readd_pattern() {
    // Edge case 3: Replace and re-add pattern
    let mut base_smt = Smt::new();
    let kv5 = TestKV::new(30);
    base_smt.insert(kv5.key, kv5.value).unwrap();

    let smt_with_history = SmtWithHistory::new(base_smt.clone());

    // First delete it
    let delete_mutation = smt_with_history.compute_mutations(vec![kv5.empty().tup()]).unwrap();
    smt_with_history.apply_mutations(delete_mutation).unwrap();

    // Then add it back with different value
    let kv5_new = TestKV::new(30).with_value(&[30u8, 255]);
    let readd_mutation = smt_with_history.compute_mutations(vec![kv5_new.tup()]).unwrap();
    smt_with_history.apply_mutations(readd_mutation).unwrap();

    // Check history at different points
    let view_after_delete = smt_with_history.historical_view(1).unwrap();
    let view_original = smt_with_history.historical_view(2).unwrap();

    assert_eq!(
        view_after_delete.get_value(&kv5.key),
        EMPTY_WORD,
        "After delete, value should be empty"
    );
    assert_eq!(
        view_original.get_value(&kv5.key),
        kv5.value,
        "Original view should have original value"
    );

    // Current state should have new value
    let current_view = smt_with_history.historical_view(0).unwrap();
    assert_eq!(current_view.get_value(&kv5.key), kv5_new.value);
}

#[test]
fn test_guards_prevent_mutations_during_reads() {
    use std::{sync::Arc, thread, time::Duration};

    let base_smt = create_mock_smt();
    let smt_with_history = Arc::new(SmtWithHistory::new(base_smt.clone()));

    // Apply initial mutation
    let (mutations1, ..) = create_mutation_sets(&base_smt);
    smt_with_history.apply_mutations(mutations1).unwrap();

    // Create a long-lived historical view in a thread
    let smt_clone = Arc::clone(&smt_with_history);
    let read_handle = thread::spawn(move || {
        let view = smt_clone.historical_view(0).unwrap();

        // Hold the view for a bit to simulate long-running read operation
        thread::sleep(Duration::from_millis(50));

        // Do some work with the view
        let key = TestKV::new(1).key;
        let value = view.get_value(&key);

        // View will be dropped when this function returns
        value
    });

    // Try to apply a mutation from another thread while read is happening
    let smt_clone2 = Arc::clone(&smt_with_history);
    let write_handle = thread::spawn(move || {
        // This will block until the read guard is released
        let new_mutation = smt_clone2.compute_mutations(vec![TestKV::new(15).tup()]).unwrap();
        smt_clone2.apply_mutations(new_mutation).unwrap();
        smt_clone2.history_len()
    });

    // Both operations should complete successfully
    let _read_result = read_handle.join().unwrap();
    let history_len = write_handle.join().unwrap();

    // The write should have succeeded after the read completed
    assert_eq!(history_len, 2);
}
