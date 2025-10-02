use miden_crypto::{
    EMPTY_WORD, Felt, ONE, WORD_SIZE, Word,
    merkle::{InnerNodeInfo, LargeSmt, RocksDbConfig, RocksDbStorage},
};
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

fn generate_entries(pair_count: usize) -> Vec<(Word, Word)> {
    (0..pair_count)
        .map(|i| {
            let key =
                Word::new([ONE, ONE, Felt::from_u64(i as u64), Felt::from_u64(i as u64 % 1000)]);
            let value = Word::new([ONE, ONE, ONE, Felt::from_u64(i as u64)]);
            (key, value)
        })
        .collect()
}

#[test]
fn rocksdb_sanity_insert_and_get() {
    let (storage, _tmp) = setup_storage();
    let mut smt = LargeSmt::<RocksDbStorage>::new(storage).unwrap();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let val = Word::new([ONE; WORD_SIZE]);

    let prev = smt.insert(key, val).unwrap();
    assert_eq!(prev, EMPTY_WORD);
    assert_eq!(smt.get_value(&key), val);
}

#[test]
fn rocksdb_persistence_reopen() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let root = smt.root().unwrap();

    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::new(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root().unwrap(), root);
}

#[test]
fn rocksdb_persistence_after_insertion() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let mut smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let key = Word::new([ONE, ONE, ONE, ONE]);
    let new_value =
        Word::new([Felt::from_u64(2), Felt::from_u64(2), Felt::from_u64(2), Felt::from_u64(2)]);
    smt.insert(key, new_value).unwrap();
    let root = smt.root().unwrap();

    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::new(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root().unwrap(), root);
}
