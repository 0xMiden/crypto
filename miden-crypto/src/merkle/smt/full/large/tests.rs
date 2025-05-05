use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{EMPTY_WORD, LargeSmt, RpoDigest, Smt};
use crate::{
    ONE, WORD_SIZE,
    merkle::smt::full::concurrent::{
        COLS_PER_SUBTREE,
        tests::{generate_entries, generate_updates},
    },
};
// LargeSMT
// --------------------------------------------------------------------------------------------

fn setup_db_path() -> PathBuf {
    let path = Path::new("test_smt");
    if path.exists() {
        std::fs::remove_dir_all(path).unwrap();
    }
    fs::create_dir_all(path).expect("Failed to create database directory");
    path.to_path_buf()
}

/// Tests that `get_value()` works as expected
#[test]
fn test_smt_get_value() {
    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2: RpoDigest = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let path = setup_db_path();
    let smt = LargeSmt::with_entries(&path, [(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = RpoDigest::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

#[test]
fn test_smt_and_large_smt_are_equivalent() {
    let entries = generate_entries(1000);
    let smt = Smt::with_entries(entries.clone()).unwrap();

    let path = setup_db_path();
    let large_smt = LargeSmt::with_entries(&path, entries).unwrap();
    assert_eq!(smt.root(), large_smt.root());
}

#[test]
fn test_compute_mutations() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    let tree = Smt::with_entries(entries.clone()).unwrap();

    let path = setup_db_path();
    let large_tree = LargeSmt::with_entries(&path, entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);
    let control = tree.compute_mutations(updates.clone());
    let mutations = large_tree.compute_mutations(updates);
    assert_eq!(mutations.root(), control.root());
    assert_eq!(mutations.old_root(), control.old_root());
    assert_eq!(mutations.node_mutations(), control.node_mutations());
    assert_eq!(mutations.new_pairs(), control.new_pairs());
}
