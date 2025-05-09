use alloc::{boxed::Box, string::ToString, vec::Vec};
use std::{path::PathBuf, sync::Arc};

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompactionStyle, DBCompressionType,
    DBIteratorWithThreadMode, IteratorMode, Options, ReadOptions, WriteBatch,
};
use winter_utils::{Deserializable, Serializable};

use super::{SmtStorage, StorageError, StorageUpdates};
use crate::merkle::{
    InnerNode, NodeIndex, RpoDigest, SmtLeaf,
    smt::{
        UnorderedMap,
        full::large::{IN_MEMORY_DEPTH, subtree::Subtree},
    },
};

const LEAVES_CF: &str = "leaves";
const SUBTREES_CF: &str = "subtrees";
const METADATA_CF: &str = "metadata";

const ROOT_KEY: &[u8] = b"smt_root";
const LEAF_COUNT_KEY: &[u8] = b"leaf_count";
const ENTRY_COUNT_KEY: &[u8] = b"entry_count";

#[derive(Debug, Clone)]
pub struct RocksDbStorage {
    db: Arc<DB>,
}

impl RocksDbStorage {
    pub fn open(path: &PathBuf) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism(rayon::current_num_threads() as i32);
        db_opts.set_max_open_files(512);

        let cache = Cache::new_lru_cache(1024 * 1024 * 1024);

        let mut leaves_table_opts = BlockBasedOptions::default();
        leaves_table_opts.set_block_cache(&cache);
        leaves_table_opts.set_bloom_filter(10.0, false);
        leaves_table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&leaves_table_opts);
        leaves_opts.set_write_buffer_size(64 * 1024 * 1024);
        leaves_opts.set_max_write_buffer_number(4);
        leaves_opts.set_min_write_buffer_number_to_merge(2);
        leaves_opts.set_compaction_style(DBCompactionStyle::Level);
        leaves_opts.set_target_file_size_base(64 * 1024 * 1024);

        let mut subtrees_table_opts = BlockBasedOptions::default();
        subtrees_table_opts.set_block_cache(&cache);
        subtrees_table_opts.set_bloom_filter(16.0, true);
        subtrees_table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        let mut subtrees_opts = Options::default();
        subtrees_opts.set_block_based_table_factory(&subtrees_table_opts);
        subtrees_opts.set_write_buffer_size(16 * 1024 * 1024);
        subtrees_opts.set_max_write_buffer_number(6);
        subtrees_opts.set_compaction_style(DBCompactionStyle::Universal);
        subtrees_opts.set_level_zero_file_num_compaction_trigger(4);
        subtrees_opts.set_target_file_size_base(8 * 1024 * 1024);

        let metadata_table_opts = BlockBasedOptions::default();
        let mut metadata_opts = Options::default();
        metadata_opts.set_block_based_table_factory(&metadata_table_opts);
        metadata_opts.set_compression_type(DBCompressionType::None);

        let cfs = vec![
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(SUBTREES_CF, subtrees_opts),
            ColumnFamilyDescriptor::new(METADATA_CF, metadata_opts),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)
            .map_err(|e| StorageError::BackendError(format!("Failed to open DB: {e}")))?;

        Ok(Self { db: Arc::new(db) })
    }

    #[inline(always)]
    fn leaf_db_key(index: u64) -> [u8; 8] {
        index.to_be_bytes()
    }

    #[inline(always)]
    fn subtree_db_key(index: NodeIndex) -> [u8; 9] {
        Subtree::subtree_key(index)
    }

    fn cf_handle(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::BackendError(format!("CF '{name}' missing")))
    }
}

impl SmtStorage for RocksDbStorage {
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self
            .db
            .get_cf(cf, ROOT_KEY)
            .map_err(|e| StorageError::BackendError(e.to_string()))?
        {
            Some(bytes) => {
                let digest = RpoDigest::read_from_bytes(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(digest))
            },
            None => Ok(None),
        }
    }

    fn set_root(&self, root: RpoDigest) -> Result<(), StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db
            .put_cf(cf, ROOT_KEY, root.to_bytes())
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn get_leaf_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self
            .db
            .get_cf(cf, LEAF_COUNT_KEY)
            .map_err(|e| StorageError::BackendError(e.to_string()))?
        {
            Some(bytes) => {
                if bytes.len() == 8 {
                    Ok(usize::from_be_bytes(bytes.try_into().unwrap()))
                } else {
                    Err(StorageError::DeserializationError(
                        "Invalid byte length for leaf count".to_string(),
                    ))
                }
            },
            None => Ok(0),
        }
    }

    fn get_entry_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self
            .db
            .get_cf(cf, ENTRY_COUNT_KEY)
            .map_err(|e| StorageError::BackendError(e.to_string()))?
        {
            Some(bytes) => {
                if bytes.len() == 8 {
                    Ok(usize::from_be_bytes(bytes.try_into().unwrap()))
                } else {
                    Err(StorageError::DeserializationError(
                        "Invalid byte length for entry count".to_string(),
                    ))
                }
            },
            None => Ok(0),
        }
    }

    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = Self::leaf_db_key(index);
        match self.db.get_cf(cf, key).map_err(|e| StorageError::BackendError(e.to_string()))? {
            Some(bytes) => {
                let leaf = SmtLeaf::read_from_bytes(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(leaf))
            },
            None => Ok(None),
        }
    }

    fn set_leaf(&self, index: u64, leaf: &SmtLeaf) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = Self::leaf_db_key(index);
        let old_bytes = self.db.get_cf(cf, key).ok().flatten();
        let value = leaf.to_bytes();
        self.db
            .put_cf(cf, key, value)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(old_bytes
            .map(|bytes| SmtLeaf::read_from_bytes(&bytes).expect("failed to deserialize leaf")))
    }

    /// Sets leaves and updates the leaf count
    fn set_leaves(&self, leaves: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let leaf_count: usize = leaves.len();
        let entry_count: usize = leaves.values().map(|leaf| leaf.entries().len()).sum();
        let mut batch = WriteBatch::default();
        for (idx, leaf) in leaves {
            let key = Self::leaf_db_key(idx);
            let value = leaf.to_bytes();
            batch.put_cf(cf, key, &value);
        }
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, entry_count.to_be_bytes());
        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let key = Self::leaf_db_key(index);
        let cf = self.cf_handle(LEAVES_CF)?;
        let old_bytes = self.db.get_cf(cf, key).ok().flatten();
        self.db
            .delete_cf(cf, key)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(old_bytes
            .map(|bytes| SmtLeaf::read_from_bytes(&bytes).expect("failed to deserialize leaf")))
    }

    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_keys: Vec<[u8; 8]> = indices.iter().map(|&idx| Self::leaf_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k.as_ref())));

        results
            .into_iter()
            .map(|result| match result {
                Ok(Some(bytes)) => SmtLeaf::read_from_bytes(&bytes)
                    .map(Some)
                    .map_err(|e| StorageError::DeserializationError(e.to_string())),
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::BackendError(e.to_string())),
            })
            .collect()
    }

    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(index);
        match self.db.get_cf(cf, key).map_err(|e| StorageError::BackendError(e.to_string()))? {
            Some(bytes) => {
                let subtree = Subtree::from_vec(index, &bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(subtree))
            },
            None => Ok(None),
        }
    }

    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let db_keys: Vec<[u8; 9]> = indices.iter().map(|&idx| Self::subtree_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k)));

        results
            .into_iter()
            .zip(indices)
            .map(|(result, index)| match result {
                Ok(Some(bytes)) => {
                    let value_vec = bytes.to_vec();
                    Subtree::from_vec(*index, &value_vec)
                        .map(Some)
                        .map_err(|e| StorageError::DeserializationError(e.to_string()))
                },
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::BackendError(e.to_string())),
            })
            .collect()
    }

    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(subtree.root_index);
        self.db
            .put_cf(cf, key, subtree.to_vec())
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn set_subtrees(&self, subtrees: Vec<Subtree>) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let mut batch = WriteBatch::default();
        let serialized: Vec<([u8; 9], Vec<u8>)> = subtrees
            .into_iter()
            .map(|subtree| {
                let key = Self::subtree_db_key(subtree.root_index);
                let value = subtree.to_vec();
                (key, value)
            })
            .collect();
        for (key, value) in serialized {
            batch.put_cf(cf, key, value);
        }
        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(index);
        self.db
            .delete_cf(cf, key)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            Err(StorageError::BackendError(
                "Cannot get inner node from upper part of the tree".to_string(),
            ))
        } else {
            let subtree_root_index = Subtree::find_subtree_root(index);
            let subtree = self.get_subtree(subtree_root_index).expect("failed to get subtree");
            if let Some(subtree) = subtree {
                Ok(subtree.get_inner_node(index))
            } else {
                Ok(None)
            }
        }
    }

    fn set_inner_node(
        &self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            Err(StorageError::BackendError(
                "Cannot set inner node in upper part of the tree".to_string(),
            ))
        } else {
            let subtree_root_index = Subtree::find_subtree_root(index);
            let mut subtree = self
                .get_subtree(subtree_root_index)?
                .unwrap_or_else(|| Subtree::new(subtree_root_index));
            let old_node = subtree.insert_inner_node(index, node);
            self.set_subtree(&subtree)?;
            Ok(old_node)
        }
    }

    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            Err(StorageError::BackendError(
                "Cannot remove inner node from upper part of the tree".to_string(),
            ))
        } else {
            let subtree_root_index = Subtree::find_subtree_root(index);
            if let Some(mut subtree) = self.get_subtree(subtree_root_index)? {
                let old_node = subtree.remove_inner_node(index);
                if subtree.is_empty() {
                    self.remove_subtree(subtree_root_index)?;
                } else {
                    self.set_subtree(&subtree)?;
                }
                Ok(old_node)
            } else {
                // Subtree not found, so the node within it is also not found.
                Ok(None)
            }
        }
    }

    fn apply(&self, updates: StorageUpdates) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let subtrees_cf = self.cf_handle(SUBTREES_CF)?;
        let metadata_cf = self.cf_handle(METADATA_CF)?;

        for (index, maybe_leaf) in updates.leaf_updates {
            let key = Self::leaf_db_key(index);
            match maybe_leaf {
                Some(leaf) => {
                    let bytes = leaf.to_bytes();
                    batch.put_cf(leaves_cf, key, bytes);
                },
                None => batch.delete_cf(leaves_cf, key),
            }
        }

        for (index, maybe_subtree) in updates.subtree_updates {
            let key = Self::subtree_db_key(index);
            match maybe_subtree {
                Some(subtree) => {
                    let bytes = subtree.to_vec();
                    batch.put_cf(subtrees_cf, key, bytes);
                },
                None => batch.delete_cf(subtrees_cf, key),
            }
        }

        if updates.leaf_count_delta != 0 || updates.entry_count_delta != 0 {
            let current_leaf_count = self.get_leaf_count()?;
            let current_entry_count = self.get_entry_count()?;

            let new_leaf_count = current_leaf_count.saturating_add_signed(updates.leaf_count_delta);
            let new_entry_count =
                current_entry_count.saturating_add_signed(updates.entry_count_delta);

            batch.put_cf(metadata_cf, LEAF_COUNT_KEY, new_leaf_count.to_be_bytes());
            batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, new_entry_count.to_be_bytes());
        }

        batch.put_cf(metadata_cf, ROOT_KEY, updates.new_root.to_bytes());

        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true); // Good for full scans
        let db_iter = self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectLeafIterator { iter: db_iter }))
    }

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        let db_iter = self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectSubtreeIterator { iter: db_iter }))
    }

    /// Returns the Inner roots of all subtrees stored at the specified depth.
    ///
    /// This method iterates directly over RocksDB keys that start with the given depth byte
    /// in the subtrees column family.
    fn get_subtree_roots_at_depth(&self, depth: u8) -> Result<Vec<(u64, RpoDigest)>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let prefix = [depth];

        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&prefix, rocksdb::Direction::Forward));

        let mut roots = Vec::new();

        for item_result in iter {
            match item_result {
                Ok((key_bytes, value_bytes)) => {
                    if key_bytes.starts_with(&prefix) {
                        let subtree_root_idx = node_index_from_key_bytes(&key_bytes)?;
                        if subtree_root_idx.depth() != depth {
                            break;
                        }

                        let subtree = Subtree::from_vec(subtree_root_idx, &value_bytes)
                            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

                        match subtree.get_inner_node(subtree_root_idx) {
                            Some(inner_node) => {
                                roots.push((subtree_root_idx.value(), inner_node.hash()));
                            },
                            None => {
                                return Err(StorageError::Other(format!(
                                    "Root node {subtree_root_idx} not found in its own deserialized subtree",
                                )));
                            },
                        }
                    } else {
                        // If the key does not start with the prefix, we can break early
                        break;
                    }
                },
                Err(e) => {
                    return Err(StorageError::BackendError(e.to_string()));
                },
            }
        }
        Ok(roots)
    }
}

struct RocksDbDirectLeafIterator<'a> {
    iter: DBIteratorWithThreadMode<'a, DB>,
}

impl Iterator for RocksDbDirectLeafIterator<'_> {
    type Item = (u64, SmtLeaf);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok((key_bytes, value_bytes))) => {
                match leaf_index_from_key_bytes(&key_bytes) {
                    Ok(leaf_idx) => {
                        match SmtLeaf::read_from_bytes(&value_bytes) {
                            Ok(leaf) => Some((leaf_idx, leaf)),
                            Err(_) => {
                                self.next() // Try next item on error
                            },
                        }
                    },
                    Err(_) => {
                        self.next() // Try next item on error
                    },
                }
            },
            Some(Err(_)) => {
                self.next() // Try next item on RocksDB error
            },
            None => None,
        }
    }
}

struct RocksDbDirectSubtreeIterator<'a> {
    iter: DBIteratorWithThreadMode<'a, DB>,
}

impl Iterator for RocksDbDirectSubtreeIterator<'_> {
    type Item = Subtree;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok((key_bytes, value_bytes))) => {
                match node_index_from_key_bytes(&key_bytes) {
                    Ok(node_idx) => {
                        let value_vec = value_bytes.into_vec();
                        match Subtree::from_vec(node_idx, &value_vec) {
                            Ok(subtree) => Some(subtree),
                            Err(_) => {
                                self.next() // Try next item
                            },
                        }
                    },
                    Err(_) => {
                        self.next() // Try next item
                    },
                }
            },
            Some(Err(_)) => {
                self.next() // Try next item
            },
            None => None,
        }
    }
}

fn leaf_index_from_key_bytes(key_bytes: &[u8]) -> Result<u64, StorageError> {
    if key_bytes.len() != 8 {
        return Err(StorageError::DeserializationError(
            "Invalid key length for leaf index".to_string(),
        ));
    }
    let arr: [u8; 8] = key_bytes
        .try_into()
        .map_err(|_| StorageError::DeserializationError("Key to [u8; 8] failed".to_string()))?;
    Ok(u64::from_be_bytes(arr))
}

fn node_index_from_key_bytes(key_bytes: &[u8]) -> Result<NodeIndex, StorageError> {
    if key_bytes.len() != 9 {
        return Err(StorageError::DeserializationError(
            "Invalid key length for node index".to_string(),
        ));
    }
    let depth = key_bytes[0];
    let value_bytes: [u8; 8] = key_bytes[1..9].try_into().map_err(|_| {
        StorageError::DeserializationError(
            "Failed to convert slice to 8-byte array for NodeIndex value".to_string(),
        )
    })?;
    let value = u64::from_be_bytes(value_bytes);
    NodeIndex::new(depth, value)
        .map_err(|e| StorageError::Other(format!("Failed to create NodeIndex: {e}")))
}
