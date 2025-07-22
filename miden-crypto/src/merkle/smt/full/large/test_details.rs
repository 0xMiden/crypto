use alloc::{collections::BTreeSet, vec::Vec};

use rand::{Rng, prelude::IteratorRandom, rng};

use super::{EMPTY_WORD, InnerNodeInfo, LargeSmt, LeafIndex, SMT_DEPTH, SmtLeaf, SmtStorage, Word};
use crate::{
    Felt, ONE, WORD_SIZE,
    merkle::smt::full::{Smt, concurrent::COLS_PER_SUBTREE},
};

pub fn generate_entries(pair_count: u64) -> Vec<(Word, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key = Word::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = Word::new([ONE, ONE, ONE, Felt::new(i)]);
            (key, value)
        })
        .collect()
}

pub fn generate_updates(entries: Vec<(Word, Word)>, updates: usize) -> Vec<(Word, Word)> {
    const REMOVAL_PROBABILITY: f64 = 0.2;
    let mut rng = rng();
    // Assertion to ensure input keys are unique
    assert!(
        entries.iter().map(|(key, _)| key).collect::<BTreeSet<_>>().len() == entries.len(),
        "Input entries contain duplicate keys!"
    );
    let mut sorted_entries: Vec<(Word, Word)> = entries
        .into_iter()
        .choose_multiple(&mut rng, updates)
        .into_iter()
        .map(|(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                Word::new([ONE, ONE, ONE, Felt::new(rng.random())])
            };
            (key, value)
        })
        .collect();
    // Sort by the 3rd Felt in the key
    sorted_entries.sort_by_key(|(key, _)| key[3].as_int());
    sorted_entries
}

pub fn create_equivalent_smts_for_testing<S: SmtStorage>(
    storage: S,
    entries: Vec<(Word, Word)>,
) -> (Smt, LargeSmt<S>) {
    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let large_smt = LargeSmt::<S>::with_entries(storage, entries).unwrap();
    (control_smt, large_smt)
}

pub fn smt_get_value<S: SmtStorage>(storage: S) {
    let key_1: Word = Word::from([ONE, ONE, ONE, ONE]);
    let key_2: Word = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = Word::new([ONE; WORD_SIZE]);
    let value_2 = Word::new([2_u32.into(); WORD_SIZE]);
    let smt = LargeSmt::<S>::with_entries(storage, [(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = Word::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

pub fn equivalent_roots<S: SmtStorage>(storage: S) {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);
    assert_eq!(control_smt.root(), large_smt.root().unwrap());
}

pub fn equivalent_openings<S: SmtStorage>(storage: S) {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries.clone());

    for (key, _) in entries {
        assert_eq!(control_smt.open(&key), large_smt.open(&key));
    }
}

pub fn equivalent_entry_sets<S: SmtStorage>(storage: S) {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut entries_control_smt_owned: Vec<(Word, Word)> = control_smt.entries().copied().collect();
    let mut entries_large_smt: Vec<(Word, Word)> =
        large_smt.entries().expect("Failed to get entries").collect();

    entries_control_smt_owned.sort_by_key(|k| k.0);
    entries_large_smt.sort_by_key(|k| k.0);

    assert_eq!(entries_control_smt_owned, entries_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves().unwrap());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries().unwrap());
}

pub fn equivalent_leaf_sets<S: SmtStorage>(storage: S) {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut leaves_control_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        control_smt.leaves().map(|(idx, leaf_ref)| (idx, leaf_ref.clone())).collect();
    let mut leaves_large_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        large_smt.leaves().expect("Failed to get leaves").collect();

    leaves_control_smt.sort_by_key(|k| k.0);
    leaves_large_smt.sort_by_key(|k| k.0);

    assert_eq!(leaves_control_smt.len(), leaves_large_smt.len());
    assert_eq!(leaves_control_smt, leaves_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves().unwrap());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries().unwrap());
}

pub fn equivalent_inner_nodes<S: SmtStorage>(storage: S) {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut control_smt_inner_nodes: Vec<InnerNodeInfo> = control_smt.inner_nodes().collect();
    let mut large_smt_inner_nodes: Vec<InnerNodeInfo> =
        large_smt.inner_nodes().expect("Failed to get inner nodes").collect();

    // Sort both vectors by hash for comparison
    control_smt_inner_nodes.sort_by_key(|info| info.value);
    large_smt_inner_nodes.sort_by_key(|info| info.value);

    assert_eq!(control_smt_inner_nodes.len(), large_smt_inner_nodes.len());
    for (control, large) in control_smt_inner_nodes.iter().zip(large_smt_inner_nodes.iter()) {
        assert_eq!(control, large);
    }
}

pub fn compute_mutations<S: SmtStorage>(storage: S) {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    let control_smt = Smt::with_entries(entries.clone()).unwrap();

    let large_tree = LargeSmt::<S>::with_entries(storage, entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);
    let control_mutations = control_smt.compute_mutations(updates.clone());

    let mutations = large_tree.compute_mutations(updates).unwrap();
    assert_eq!(mutations.root(), control_mutations.root());
    assert_eq!(mutations.old_root(), control_mutations.old_root());
    assert_eq!(mutations.node_mutations(), control_mutations.node_mutations());
    assert_eq!(mutations.new_pairs(), control_mutations.new_pairs());
}

pub fn empty_smt<S: SmtStorage>(storage: S) {
    let large_smt = LargeSmt::<S>::new(storage).expect("Failed to create empty SMT");

    let empty_control_smt = Smt::new();
    assert_eq!(large_smt.root().unwrap(), empty_control_smt.root(), "Empty SMT root mismatch");

    let random_key = Word::from([ONE, 2_u32.into(), 3_u32.into(), 4_u32.into()]);
    assert_eq!(
        large_smt.get_value(&random_key),
        EMPTY_WORD,
        "get_value on empty SMT should return EMPTY_WORD"
    );

    assert_eq!(
        large_smt.entries().expect("Failed to get entries").count(),
        0,
        "Empty SMT should have no entries"
    );
    assert_eq!(
        large_smt.leaves().expect("Failed to get leaves").count(),
        0,
        "Empty SMT should have no leaves"
    );
    assert_eq!(
        large_smt.inner_nodes().expect("Failed to get inner nodes").count(),
        0,
        "Empty SMT should have no inner nodes"
    );
}

pub fn single_entry_smt<S: SmtStorage>(storage: S) {
    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = Word::new([ONE; WORD_SIZE]);

    // Create SMT with a single entry
    let mut smt = LargeSmt::<S>::with_entries(storage, [(key, value)]).unwrap();

    // Check root
    let control_smt_single = Smt::with_entries([(key, value)]).unwrap();
    assert_eq!(smt.root().unwrap(), control_smt_single.root(), "Single entry SMT root mismatch");

    // Check get_value for the existing key
    assert_eq!(smt.get_value(&key), value, "get_value for existing key failed");

    // Check get_value for a non-existing key
    let other_key = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    assert_eq!(smt.get_value(&other_key), EMPTY_WORD, "get_value for non-existing key failed");

    // Check entries iterator
    let entries: Vec<_> = smt.entries().expect("Failed to get entries").collect();
    assert_eq!(entries.len(), 1, "Single entry SMT should have one entry");
    assert_eq!(entries[0], (key, value), "Single entry SMT entry mismatch");

    // Update the entry
    let new_value = Word::new([2_u32.into(); WORD_SIZE]);
    let mutations = smt.compute_mutations(vec![(key, new_value)]).unwrap();

    // test opening before mutations
    assert_eq!(
        smt.open(&key),
        control_smt_single.open(&key),
        "Opening before mutations mismatch"
    );

    smt.apply_mutations(mutations).unwrap();

    let control_smt_updated = Smt::with_entries([(key, new_value)]).unwrap();
    assert_eq!(smt.root().unwrap(), control_smt_updated.root(), "Updated SMT root mismatch");
    assert_eq!(smt.get_value(&key), new_value, "get_value after update failed");

    // test opening after mutations
    assert_eq!(
        smt.open(&key),
        control_smt_updated.open(&key),
        "Opening after mutations mismatch"
    );

    // "Delete" the entry by updating its value to EMPTY_WORD
    let mutations_delete = smt.compute_mutations(vec![(key, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations_delete).unwrap();

    let empty_control_smt = Smt::new();
    assert_eq!(
        smt.root().unwrap(),
        empty_control_smt.root(),
        "SMT root after deletion mismatch"
    );
    assert_eq!(smt.get_value(&key), EMPTY_WORD, "get_value after deletion failed");
    assert_eq!(
        smt.entries().expect("Failed to get entries").count(),
        0,
        "SMT should have no entries after deletion"
    );
}

pub fn duplicate_key_insertion<S: SmtStorage>(storage: S) {
    let key = Word::from([ONE, ONE, ONE, ONE]);
    let value1 = Word::new([ONE; WORD_SIZE]);
    let value2 = Word::new([2_u32.into(); WORD_SIZE]);

    let entries = vec![(key, value1), (key, value2)];

    let result = LargeSmt::<S>::with_entries(storage, entries);
    assert!(result.is_err(), "Expected an error when inserting duplicate keys");
}

pub fn delete_entry<S: SmtStorage>(storage: S) {
    let key1 = Word::new([ONE, ONE, ONE, ONE]);
    let value1 = Word::new([ONE; WORD_SIZE]);
    let key2 = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    let value2 = Word::new([2_u32.into(); WORD_SIZE]);
    let key3 = Word::from([3_u32, 3_u32, 3_u32, 3_u32]);
    let value3 = Word::new([3_u32.into(); WORD_SIZE]);

    let initial_entries = vec![(key1, value1), (key2, value2), (key3, value3)];

    let mut smt = LargeSmt::<S>::with_entries(storage, initial_entries.clone()).unwrap();

    // "Delete" key2 by updating its value to EMPTY_WORD
    let mutations = smt.compute_mutations(vec![(key2, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations).unwrap();

    // Check that key2 now returns EMPTY_WORD
    assert_eq!(
        smt.get_value(&key2),
        EMPTY_WORD,
        "get_value for deleted key should be EMPTY_WORD"
    );

    // Check that key2 is not in entries()
    let current_entries: Vec<_> = smt.entries().expect("Failed to get entries").collect();
    assert!(
        !current_entries.iter().any(|(k, _v)| k == &key2),
        "Deleted key should not be in entries"
    );
    assert_eq!(current_entries.len(), 2, "SMT should have 2 entries after deletion");

    // Check that other keys are still present
    assert_eq!(smt.get_value(&key1), value1, "Value for key1 changed after deleting key2");
    assert_eq!(smt.get_value(&key3), value3, "Value for key3 changed after deleting key2");

    // Verify the root hash against a control SMT with the remaining entries
    let remaining_entries = vec![(key1, value1), (key3, value3)];
    let control_smt_after_delete = Smt::with_entries(remaining_entries).unwrap();
    assert_eq!(
        smt.root().unwrap(),
        control_smt_after_delete.root(),
        "SMT root mismatch after deletion"
    );
}

pub fn insert_entry<S: SmtStorage>(storage: S) {
    let initial_entries = generate_entries(100);

    let mut large_smt = LargeSmt::<S>::with_entries(storage, initial_entries.clone()).unwrap();
    let mut control_smt = Smt::with_entries(initial_entries.clone()).unwrap();

    assert_eq!(
        large_smt.num_entries().unwrap(),
        control_smt.num_entries(),
        "Number of entries mismatch"
    );
    assert_eq!(
        large_smt.num_leaves().unwrap(),
        control_smt.num_leaves(),
        "Number of leaves mismatch"
    );

    // Generate new key that wasn't in the initial construction
    let new_key = Word::from([100_u32, 100_u32, 100_u32, 100_u32]);
    let new_value = Word::new([100_u32.into(); WORD_SIZE]);

    let old_value = large_smt.insert(new_key, new_value);
    let control_old_value = control_smt.insert(new_key, new_value);
    assert_eq!(old_value, control_old_value, "Old values mismatch");
    assert_eq!(old_value, EMPTY_WORD, "Expected empty value");

    assert_eq!(
        large_smt.num_entries().unwrap(),
        control_smt.num_entries(),
        "Number of entries mismatch"
    );
    assert_eq!(
        large_smt.num_leaves().unwrap(),
        control_smt.num_leaves(),
        "Number of leaves mismatch"
    );

    // Verify the value was inserted
    assert_eq!(large_smt.get_value(&new_key), new_value, "Value mismatch");
    assert_eq!(control_smt.get_value(&new_key), new_value, "Value mismatch");

    // Verify roots match
    assert_eq!(large_smt.root().unwrap(), control_smt.root(), "Roots don't match after insert");

    // Try to open a proof for the inserted key
    let large_proof = large_smt.open(&new_key);
    let control_proof = control_smt.open(&new_key);
    assert_eq!(large_proof, control_proof, "Proofs don't match");

    // Verify we can still open proofs for the original keys
    for (key, _) in initial_entries {
        let large_proof = large_smt.open(&key);
        let control_proof = control_smt.open(&key);
        assert_eq!(large_proof, control_proof, "Proofs don't match for original key: {key:?}");
    }
}

pub fn mutations_revert<S: SmtStorage>(storage: S) {
    let mut smt = LargeSmt::<S>::new(storage).unwrap();

    let key_1: Word = Word::new([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: Word = Word::new([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(2)]);
    let key_3: Word = Word::new([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(3)]);

    let value_1 = Word::new([ONE; WORD_SIZE]);
    let value_2 = Word::new([2_u32.into(); WORD_SIZE]);
    let value_3 = Word::new([3_u32.into(); WORD_SIZE]);

    smt.insert(key_1, value_1);
    smt.insert(key_2, value_2);

    let mutations = smt
        .compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)])
        .unwrap();

    let original_root = smt.root().unwrap();
    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();
    assert_eq!(revert.old_root, smt.root().unwrap(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), original_root, "reverse mutations new root did not match");

    smt.apply_mutations(revert).unwrap();

    assert_eq!(
        smt.root().unwrap(),
        original_root,
        "SMT with applied revert mutations did not match original SMT"
    );
}
