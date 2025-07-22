use super::{MemoryStorage, test_details::*};

// LargeSMT
// --------------------------------------------------------------------------------------------

#[test]
fn test_smt_get_value() {
    let storage = MemoryStorage::new();
    smt_get_value(storage);
}

#[test]
fn test_equivalent_roots() {
    let storage = MemoryStorage::new();
    equivalent_roots(storage);
}

#[test]
fn test_equivalent_openings() {
    let storage = MemoryStorage::new();
    equivalent_openings(storage);
}

#[test]
fn test_equivalent_entry_sets() {
    let storage = MemoryStorage::new();
    equivalent_entry_sets(storage);
}

#[test]
fn test_equivalent_leaf_sets() {
    let storage = MemoryStorage::new();
    equivalent_leaf_sets(storage);
}

#[test]
fn test_equivalent_inner_nodes() {
    let storage = MemoryStorage::new();
    equivalent_inner_nodes(storage);
}

#[test]
fn test_compute_mutations() {
    let storage = MemoryStorage::new();
    compute_mutations(storage);
}

#[test]
fn test_empty_smt() {
    let storage = MemoryStorage::new();
    empty_smt(storage);
}

#[test]
fn test_single_entry_smt() {
    let storage = MemoryStorage::new();
    single_entry_smt(storage);
}

#[test]
fn test_duplicate_key_insertion() {
    let storage = MemoryStorage::new();
    duplicate_key_insertion(storage);
}

#[test]
fn test_delete_entry() {
    let storage = MemoryStorage::new();
    delete_entry(storage);
}

#[test]
fn test_insert_entry() {
    let storage = MemoryStorage::new();
    insert_entry(storage);
}

#[test]
fn test_mutations_revert() {
    let storage = MemoryStorage::new();
    mutations_revert(storage);
}
