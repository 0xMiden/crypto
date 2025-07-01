use miden_crypto::merkle::test_details;
use miden_crypto::merkle::{InnerNodeInfo, LargeSmt, RocksDbConfig, RocksDbStorage};
use tempfile::TempDir;

fn setup_storage() -> (RocksDbStorage, TempDir) {
    let temp_dir = tempfile::Builder::new()
        .prefix("test_smt_rocksdb_")
        .tempdir()
        .expect("Failed to create temporary directory for RocksDB test");

    let db_path = temp_dir.path().to_path_buf();

    let storage = RocksDbStorage::open(RocksDbConfig::new(db_path))
        .expect("Failed to open RocksDbStorage in temporary directory");
    (storage, temp_dir)
}

#[test]
fn rocksdb_test_smt_get_value() {
    let (storage, _temp_dir) = setup_storage();
    test_details::smt_get_value(storage);
}

#[test]
fn rocksdb_test_equivalent_roots() {
    let (storage, _temp_dir) = setup_storage();
    test_details::equivalent_roots(storage);
}

#[test]
fn rocksdb_test_equivalent_openings() {
    let (storage, _temp_dir) = setup_storage();
    test_details::equivalent_openings(storage);
}

#[test]
fn rocksdb_test_equivalent_entry_sets() {
    let (storage, _temp_dir) = setup_storage();
    test_details::equivalent_entry_sets(storage);
}

#[test]
fn rocksdb_test_equivalent_leaf_sets() {
    let (storage, _temp_dir) = setup_storage();
    test_details::equivalent_leaf_sets(storage);
}

#[test]
fn rocksdb_test_equivalent_inner_nodes() {
    let (storage, _temp_dir) = setup_storage();
    test_details::equivalent_inner_nodes(storage);
}

#[test]
fn rocksdb_test_compute_mutations() {
    let (storage, _temp_dir) = setup_storage();
    test_details::compute_mutations(storage);
}

#[test]
fn rocksdb_test_empty_smt() {
    let (storage, _temp_dir) = setup_storage();
    test_details::empty_smt(storage);
}

#[test]
fn rocksdb_test_single_entry_smt() {
    let (storage, _temp_dir) = setup_storage();
    test_details::single_entry_smt(storage);
}

#[test]
fn rocksdb_test_duplicate_key_insertion() {
    let (storage, _temp_dir) = setup_storage();
    test_details::duplicate_key_insertion(storage);
}

#[test]
fn rocksdb_test_delete_entry() {
    let (storage, _temp_dir) = setup_storage();
    test_details::delete_entry(storage);
}

#[test]
fn rocksdb_test_mutations_revert() {
    let (storage, _temp_dir) = setup_storage();
    test_details::mutations_revert(storage);
}

#[test]
fn rocksdb_test_reopening_smt() {
    let entries = test_details::generate_entries(1000);

    // Create SMT with a single entry
    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let root = smt.root();

    // collect all the inner nodes
    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    // Reopen the db using the same path
    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::new(reopened_storage).unwrap();

    // again collect all the inner nodes
    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    // check if the inner nodes match
    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
}

#[test]
fn rocksdb_test_reopening_smt_after_insertion() {
    let entries = test_details::generate_entries(1000);

    // Create SMT with a single entry
    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let root = smt.root();

    // collect all the inner nodes
    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    // Reopen the db using the same path
    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::new(reopened_storage).unwrap();

    // again collect all the inner nodes
    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    // check if the inner nodes match
    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
}
