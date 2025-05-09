use alloc::vec::Vec;

#[cfg(feature = "rocksdb")]
use super::RocksDbStorage;
use super::{
    EMPTY_WORD, InnerNodeInfo, LargeSmt, LeafIndex, RpoDigest, SMT_DEPTH, Smt, SmtLeaf, Word,
};

#[cfg(feature = "rocksdb")]
type Storage = RocksDbStorage;

#[cfg(not(feature = "rocksdb"))]
use super::MemoryStorage;
#[cfg(not(feature = "rocksdb"))]
type Storage = MemoryStorage;

use crate::{
    ONE, WORD_SIZE,
    merkle::smt::full::concurrent::{
        COLS_PER_SUBTREE,
        tests::{generate_entries, generate_updates},
    },
};
// LargeSMT
// --------------------------------------------------------------------------------------------

#[cfg(feature = "rocksdb")]
fn setup_storage() -> RocksDbStorage {
    use std::{fs, path::PathBuf};
    let path = PathBuf::from("test_smt");
    if path.exists() {
        std::fs::remove_dir_all(path.clone()).unwrap();
    }
    fs::create_dir_all(path.clone()).expect("Failed to create database directory");
    RocksDbStorage::open(&path).unwrap()
}

#[cfg(not(feature = "rocksdb"))]
fn setup_storage() -> MemoryStorage {
    MemoryStorage::new()
}

fn create_equivalent_smts_for_testing(entries: Vec<(RpoDigest, Word)>) -> (Smt, LargeSmt<Storage>) {
    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let storage = setup_storage();
    let large_smt = LargeSmt::<Storage>::with_entries(storage, entries).unwrap();
    (control_smt, large_smt)
}

#[test]
fn test_smt_get_value() {
    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2: RpoDigest = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let storage = setup_storage();

    let smt =
        LargeSmt::<Storage>::with_entries(storage, [(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = RpoDigest::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

#[test]
fn test_equivalent_roots() {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(entries);
    assert_eq!(control_smt.root(), large_smt.root());
}

#[test]
fn test_equivalent_openings() {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(entries.clone());

    for (key, _) in entries {
        assert_eq!(control_smt.open(&key), large_smt.open(&key));
    }
}

#[test]
fn test_equivalent_entry_sets() {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(entries);

    let mut entries_control_smt_owned: Vec<(RpoDigest, Word)> = control_smt.entries().copied().collect();
    let mut entries_large_smt: Vec<(RpoDigest, Word)> = large_smt.entries().collect();

    entries_control_smt_owned.sort_by_key(|k| k.0);
    entries_large_smt.sort_by_key(|k| k.0);

    assert_eq!(entries_control_smt_owned, entries_large_smt);
}

#[test]
fn test_equivalent_leaf_sets() {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(entries);

    let mut leaves_control_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        control_smt.leaves().map(|(idx, leaf_ref)| (idx, leaf_ref.clone())).collect();
    let mut leaves_large_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> = large_smt.leaves().collect();

    leaves_control_smt.sort_by_key(|k| k.0);
    leaves_large_smt.sort_by_key(|k| k.0);

    assert_eq!(leaves_control_smt.len(), leaves_large_smt.len());
    assert_eq!(leaves_control_smt, leaves_large_smt);
}

#[test]
fn test_equivalent_inner_nodes() {
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(entries);

    let mut control_smt_inner_nodes: Vec<InnerNodeInfo> = control_smt.inner_nodes().collect();
    let mut large_smt_inner_nodes: Vec<InnerNodeInfo> = large_smt.inner_nodes().collect();

    control_smt_inner_nodes.sort_by_key(|info| info.value);
    large_smt_inner_nodes.sort_by_key(|info| info.value);

    assert_eq!(control_smt_inner_nodes.len(), large_smt_inner_nodes.len());
    assert_eq!(control_smt_inner_nodes, large_smt_inner_nodes);
}

#[test]
fn test_compute_mutations() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    let control_smt = Smt::with_entries(entries.clone()).unwrap();

    let storage = setup_storage();
    let large_tree = LargeSmt::<Storage>::with_entries(storage, entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);
    let control_mutations = control_smt.compute_mutations(updates.clone());

    let mutations = large_tree.compute_mutations(updates);
    assert_eq!(mutations.root(), control_mutations.root());
    assert_eq!(mutations.old_root(), control_mutations.old_root());
    assert_eq!(mutations.node_mutations(), control_mutations.node_mutations());
    assert_eq!(mutations.new_pairs(), control_mutations.new_pairs());
}

#[test]
fn test_empty_smt() {
    let storage = setup_storage();
    let large_smt = LargeSmt::<Storage>::new(storage).expect("Failed to create empty SMT");

    let empty_control_smt = Smt::new();
    assert_eq!(large_smt.root(), empty_control_smt.root(), "Empty SMT root mismatch");

    let random_key = RpoDigest::from([ONE, 2_u32.into(), 3_u32.into(), 4_u32.into()]);
    assert_eq!(
        large_smt.get_value(&random_key),
        EMPTY_WORD,
        "get_value on empty SMT should return EMPTY_WORD"
    );

    assert_eq!(large_smt.entries().count(), 0, "Empty SMT should have no entries");
    assert_eq!(large_smt.leaves().count(), 0, "Empty SMT should have no leaves");
    assert_eq!(large_smt.inner_nodes().count(), 0, "Empty SMT should have no inner nodes");
}

#[test]
fn test_single_entry_smt() {
    let storage = setup_storage();
    let key = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let value = [ONE; WORD_SIZE];

    // Create SMT with a single entry
    let mut smt = LargeSmt::<Storage>::with_entries(storage, [(key, value)]).unwrap();

    // Check root
    let control_smt_single = Smt::with_entries([(key, value)]).unwrap();
    assert_eq!(smt.root(), control_smt_single.root(), "Single entry SMT root mismatch");

    // Check get_value for the existing key
    assert_eq!(smt.get_value(&key), value, "get_value for existing key failed");

    // Check get_value for a non-existing key
    let other_key = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);
    assert_eq!(smt.get_value(&other_key), EMPTY_WORD, "get_value for non-existing key failed");

    // Check entries iterator
    let entries: Vec<_> = smt.entries().collect();
    assert_eq!(entries.len(), 1, "Single entry SMT should have one entry");
    assert_eq!(entries[0], (key, value), "Single entry SMT entry mismatch");

    // Update the entry
    let new_value = [2_u32.into(); WORD_SIZE];
    let mutations = smt.compute_mutations(vec![(key, new_value)]);
    smt.apply_mutations(mutations).unwrap();

    let control_smt_updated = Smt::with_entries([(key, new_value)]).unwrap();
    assert_eq!(smt.root(), control_smt_updated.root(), "Updated SMT root mismatch");
    assert_eq!(smt.get_value(&key), new_value, "get_value after update failed");

    // "Delete" the entry by updating its value to EMPTY_WORD
    let mutations_delete = smt.compute_mutations(vec![(key, EMPTY_WORD)]);
    smt.apply_mutations(mutations_delete).unwrap();

    let empty_control_smt = Smt::new();
    assert_eq!(smt.root(), empty_control_smt.root(), "SMT root after deletion mismatch");
    assert_eq!(smt.get_value(&key), EMPTY_WORD, "get_value after deletion failed");
    assert_eq!(smt.entries().count(), 0, "SMT should have no entries after deletion");
}

#[test]
#[cfg(feature = "rocksdb")]
fn test_reopening_smt() {
    use std::path::PathBuf;
    let storage = setup_storage();
    let entries = generate_entries(1000);

    // Create SMT with a single entry
    let smt = LargeSmt::<Storage>::with_entries(storage, entries).unwrap();
    let root = smt.root();
    // collect all the inner nodes
    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let path = PathBuf::from("test_smt");
    let storage = RocksDbStorage::open(&path).unwrap();
    let smt = LargeSmt::<Storage>::new(storage).unwrap();

    // again collect all the inner nodes
    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    // check if the inner nodes match
    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
}

#[test]
fn test_duplicate_key_insertion() {
    let storage = setup_storage();
    let key = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let value1 = [ONE; WORD_SIZE];
    let value2 = [2_u32.into(); WORD_SIZE];

    let entries = vec![(key, value1), (key, value2)];

    let result = LargeSmt::<Storage>::with_entries(storage, entries);
    assert!(result.is_err(), "Expected an error when inserting duplicate keys");
}

#[test]
fn test_delete_entry() {
    let key1 = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let value1 = [ONE; WORD_SIZE];
    let key2 = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);
    let value2 = [2_u32.into(); WORD_SIZE];
    let key3 = RpoDigest::from([3_u32, 3_u32, 3_u32, 3_u32]);
    let value3 = [3_u32.into(); WORD_SIZE];

    let initial_entries = vec![(key1, value1), (key2, value2), (key3, value3)];

    let storage = setup_storage();
    let mut smt = LargeSmt::<Storage>::with_entries(storage, initial_entries.clone()).unwrap();

    // "Delete" key2 by updating its value to EMPTY_WORD
    let mutations = smt.compute_mutations(vec![(key2, EMPTY_WORD)]);
    smt.apply_mutations(mutations).unwrap();

    // Check that key2 now returns EMPTY_WORD
    assert_eq!(
        smt.get_value(&key2),
        EMPTY_WORD,
        "get_value for deleted key should be EMPTY_WORD"
    );

    // Check that key2 is not in entries()
    let current_entries: Vec<_> = smt.entries().collect();
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
    assert_eq!(smt.root(), control_smt_after_delete.root(), "SMT root mismatch after deletion");
}
