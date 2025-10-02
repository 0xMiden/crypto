use alloc::{collections::BTreeSet, vec::Vec};

use rand::{Rng, prelude::IteratorRandom, rng};

use super::MemoryStorage;
use crate::{
    EMPTY_WORD, Felt, ONE, WORD_SIZE,
    merkle::{
        InnerNodeInfo, LargeSmt, LeafIndex, SMT_DEPTH, SmtLeaf,
        smt::full::{Smt, concurrent::COLS_PER_SUBTREE},
    },
};

fn generate_entries(pair_count: u64) -> Vec<(crate::Word, crate::Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key = crate::Word::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = crate::Word::new([ONE, ONE, ONE, Felt::new(i)]);
            (key, value)
        })
        .collect()
}

fn generate_updates(
    entries: Vec<(crate::Word, crate::Word)>,
    updates: usize,
) -> Vec<(crate::Word, crate::Word)> {
    const REMOVAL_PROBABILITY: f64 = 0.2;
    let mut rng = rng();
    assert!(
        entries.iter().map(|(key, _)| key).collect::<BTreeSet<_>>().len() == entries.len(),
        "Input entries contain duplicate keys!"
    );
    let mut sorted_entries: Vec<(crate::Word, crate::Word)> = entries
        .into_iter()
        .choose_multiple(&mut rng, updates)
        .into_iter()
        .map(|(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                crate::Word::new([ONE, ONE, ONE, Felt::new(rng.random())])
            };
            (key, value)
        })
        .collect();
    sorted_entries.sort_by_key(|(key, _)| key[3].as_int());
    sorted_entries
}

fn create_equivalent_smts_for_testing<S: super::SmtStorage>(
    storage: S,
    entries: Vec<(crate::Word, crate::Word)>,
) -> (Smt, LargeSmt<S>) {
    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let large_smt = LargeSmt::<S>::with_entries(storage, entries).unwrap();
    (control_smt, large_smt)
}

#[test]
fn test_smt_get_value() {
    let storage = MemoryStorage::new();
    let key_1: crate::Word = crate::Word::from([ONE, ONE, ONE, ONE]);
    let key_2: crate::Word = crate::Word::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = crate::Word::new([ONE; WORD_SIZE]);
    let value_2 = crate::Word::new([2_u32.into(); WORD_SIZE]);
    let smt = LargeSmt::<_>::with_entries(storage, [(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    let key_no_value = crate::Word::from([42_u32, 42_u32, 42_u32, 42_u32]);
    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

#[test]
fn test_equivalent_roots() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);
    assert_eq!(control_smt.root(), large_smt.root().unwrap());
}

#[test]
fn test_equivalent_openings() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries.clone());

    for (key, _) in entries {
        assert_eq!(control_smt.open(&key), large_smt.open(&key));
    }
}

#[test]
fn test_equivalent_entry_sets() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut entries_control_smt_owned: Vec<(crate::Word, crate::Word)> =
        control_smt.entries().copied().collect();
    let mut entries_large_smt: Vec<(crate::Word, crate::Word)> =
        large_smt.entries().unwrap().collect();

    entries_control_smt_owned.sort_by_key(|k| k.0);
    entries_large_smt.sort_by_key(|k| k.0);

    assert_eq!(entries_control_smt_owned, entries_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves().unwrap());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries().unwrap());
}

#[test]
fn test_equivalent_leaf_sets() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut leaves_control_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        control_smt.leaves().map(|(idx, leaf_ref)| (idx, leaf_ref.clone())).collect();
    let mut leaves_large_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        large_smt.leaves().unwrap().collect();

    leaves_control_smt.sort_by_key(|k| k.0);
    leaves_large_smt.sort_by_key(|k| k.0);

    assert_eq!(leaves_control_smt.len(), leaves_large_smt.len());
    assert_eq!(leaves_control_smt, leaves_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves().unwrap());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries().unwrap());
}

#[test]
fn test_equivalent_inner_nodes() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut control_smt_inner_nodes: Vec<InnerNodeInfo> = control_smt.inner_nodes().collect();
    let mut large_smt_inner_nodes: Vec<InnerNodeInfo> = large_smt.inner_nodes().unwrap().collect();

    control_smt_inner_nodes.sort_by_key(|info| info.value);
    large_smt_inner_nodes.sort_by_key(|info| info.value);

    assert_eq!(control_smt_inner_nodes.len(), large_smt_inner_nodes.len());
    assert_eq!(control_smt_inner_nodes, large_smt_inner_nodes);
}

#[test]
fn test_compute_mutations() {
    let storage = MemoryStorage::new();
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let large_tree = LargeSmt::<_>::with_entries(storage, entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);
    let control_mutations = control_smt.compute_mutations(updates.clone()).unwrap();
    let mutations = large_tree.compute_mutations(updates).unwrap();
    assert_eq!(mutations.root(), control_mutations.root());
    assert_eq!(mutations.old_root(), control_mutations.old_root());
    assert_eq!(mutations.node_mutations(), control_mutations.node_mutations());
    assert_eq!(mutations.new_pairs(), control_mutations.new_pairs());
}

#[test]
fn test_empty_smt() {
    let storage = MemoryStorage::new();
    let large_smt = LargeSmt::<_>::new(storage).expect("Failed to create empty SMT");

    let empty_control_smt = Smt::new();
    assert_eq!(large_smt.root().unwrap(), empty_control_smt.root(), "Empty SMT root mismatch");

    let random_key = crate::Word::from([ONE, 2_u32.into(), 3_u32.into(), 4_u32.into()]);
    assert_eq!(
        large_smt.get_value(&random_key),
        EMPTY_WORD,
        "get_value on empty SMT should return EMPTY_WORD"
    );

    assert_eq!(large_smt.entries().unwrap().count(), 0, "Empty SMT should have no entries");
    assert_eq!(large_smt.leaves().unwrap().count(), 0, "Empty SMT should have no leaves");
    assert_eq!(
        large_smt.inner_nodes().unwrap().count(),
        0,
        "Empty SMT should have no inner nodes"
    );
}

#[test]
fn test_single_entry_smt() {
    let storage = MemoryStorage::new();
    let key = crate::Word::new([ONE, ONE, ONE, ONE]);
    let value = crate::Word::new([ONE; WORD_SIZE]);

    let mut smt = LargeSmt::<_>::with_entries(storage, [(key, value)]).unwrap();

    let control_smt_single = Smt::with_entries([(key, value)]).unwrap();
    assert_eq!(smt.root().unwrap(), control_smt_single.root(), "Single entry SMT root mismatch");

    assert_eq!(smt.get_value(&key), value, "get_value for existing key failed");

    let other_key = crate::Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    assert_eq!(smt.get_value(&other_key), EMPTY_WORD, "get_value for non-existing key failed");

    let entries: Vec<_> = smt.entries().unwrap().collect();
    assert_eq!(entries.len(), 1, "Single entry SMT should have one entry");
    assert_eq!(entries[0], (key, value), "Single entry SMT entry mismatch");

    let new_value = crate::Word::new([2_u32.into(); WORD_SIZE]);
    let mutations = smt.compute_mutations(vec![(key, new_value)]).unwrap();

    assert_eq!(
        smt.open(&key),
        control_smt_single.open(&key),
        "Opening before mutations mismatch"
    );

    smt.apply_mutations(mutations).unwrap();

    let control_smt_updated = Smt::with_entries([(key, new_value)]).unwrap();
    assert_eq!(smt.root().unwrap(), control_smt_updated.root(), "Updated SMT root mismatch");
    assert_eq!(smt.get_value(&key), new_value, "get_value after update failed");

    assert_eq!(
        smt.open(&key),
        control_smt_updated.open(&key),
        "Opening after mutations mismatch"
    );

    let mutations_delete = smt.compute_mutations(vec![(key, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations_delete).unwrap();

    let empty_control_smt = Smt::new();
    assert_eq!(
        smt.root().unwrap(),
        empty_control_smt.root(),
        "SMT root after deletion mismatch"
    );
    assert_eq!(smt.get_value(&key), EMPTY_WORD, "get_value after deletion failed");
    assert_eq!(smt.entries().unwrap().count(), 0, "SMT should have no entries after deletion");
}

#[test]
fn test_duplicate_key_insertion() {
    let storage = MemoryStorage::new();
    let key = crate::Word::from([ONE, ONE, ONE, ONE]);
    let value1 = crate::Word::new([ONE; WORD_SIZE]);
    let value2 = crate::Word::new([2_u32.into(); WORD_SIZE]);

    let entries = vec![(key, value1), (key, value2)];

    let result = LargeSmt::<_>::with_entries(storage, entries);
    assert!(result.is_err(), "Expected an error when inserting duplicate keys");
}

#[test]
fn test_delete_entry() {
    let storage = MemoryStorage::new();
    let key1 = crate::Word::new([ONE, ONE, ONE, ONE]);
    let value1 = crate::Word::new([ONE; WORD_SIZE]);
    let key2 = crate::Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    let value2 = crate::Word::new([2_u32.into(); WORD_SIZE]);
    let key3 = crate::Word::from([3_u32, 3_u32, 3_u32, 3_u32]);
    let value3 = crate::Word::new([3_u32.into(); WORD_SIZE]);

    let initial_entries = vec![(key1, value1), (key2, value2), (key3, value3)];

    let mut smt = LargeSmt::<_>::with_entries(storage, initial_entries.clone()).unwrap();

    let mutations = smt.compute_mutations(vec![(key2, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations).unwrap();

    assert_eq!(
        smt.get_value(&key2),
        EMPTY_WORD,
        "get_value for deleted key should be EMPTY_WORD"
    );

    let current_entries: Vec<_> = smt.entries().unwrap().collect();
    assert!(
        !current_entries.iter().any(|(k, _v)| k == &key2),
        "Deleted key should not be in entries"
    );
    assert_eq!(current_entries.len(), 2, "SMT should have 2 entries after deletion");

    assert_eq!(smt.get_value(&key1), value1, "Value for key1 changed after deleting key2");
    assert_eq!(smt.get_value(&key3), value3, "Value for key3 changed after deleting key2");

    let remaining_entries = vec![(key1, value1), (key3, value3)];
    let control_smt_after_delete = Smt::with_entries(remaining_entries).unwrap();
    assert_eq!(
        smt.root().unwrap(),
        control_smt_after_delete.root(),
        "SMT root mismatch after deletion"
    );
}

#[test]
fn test_insert_entry() {
    let storage = MemoryStorage::new();
    let initial_entries = generate_entries(100);

    let mut large_smt = LargeSmt::<_>::with_entries(storage, initial_entries.clone()).unwrap();
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

    let new_key = crate::Word::from([100_u32, 100_u32, 100_u32, 100_u32]);
    let new_value = crate::Word::new([100_u32.into(); WORD_SIZE]);

    let old_value = large_smt.insert(new_key, new_value).unwrap();
    let control_old_value = control_smt.insert(new_key, new_value).unwrap();
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

    assert_eq!(large_smt.get_value(&new_key), new_value, "Value mismatch");
    assert_eq!(control_smt.get_value(&new_key), new_value, "Value mismatch");

    assert_eq!(large_smt.root().unwrap(), control_smt.root(), "Roots don't match after insert");

    let large_proof = large_smt.open(&new_key);
    let control_proof = control_smt.open(&new_key);
    assert_eq!(large_proof, control_proof, "Proofs don't match");

    for (key, _) in initial_entries {
        let large_proof = large_smt.open(&key);
        let control_proof = control_smt.open(&key);
        assert_eq!(large_proof, control_proof, "Proofs don't match for original key: {key:?}");
    }
}

#[test]
fn test_mutations_revert() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::new(storage).unwrap();

    let key_1: crate::Word = crate::Word::new([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: crate::Word =
        crate::Word::new([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(2)]);
    let key_3: crate::Word =
        crate::Word::new([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(3)]);

    let value_1 = crate::Word::new([ONE; WORD_SIZE]);
    let value_2 = crate::Word::new([2_u32.into(); WORD_SIZE]);
    let value_3 = crate::Word::new([3_u32.into(); WORD_SIZE]);

    smt.insert(key_1, value_1).unwrap();
    smt.insert(key_2, value_2).unwrap();

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
