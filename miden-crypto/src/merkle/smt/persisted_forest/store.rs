use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::cmp;
use std::{path::PathBuf, sync::Arc};

use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, Options, WriteBatch};
use thiserror::Error;

use crate::{
    Map, Word, WordError,
    hash::rpo::Rpo256,
    merkle::{
        EmptySubtreeRoots, MerkleError, MerklePath, MerkleProof, NodeIndex, SMT_DEPTH, SmtLeaf,
    },
};
use winter_utils::{Deserializable, Serializable};

const NODES_CF: &str = "forest_nodes";
const LEAVES_CF: &str = "forest_leaves";
const ROOTS_CF: &str = "forest_roots";

#[derive(Debug, Clone)]
pub struct RocksDbForestConfig {
    pub(crate) path: PathBuf,
    pub(crate) cache_size: usize,
    pub(crate) max_open_files: i32,
}

impl RocksDbForestConfig {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            cache_size: 128 << 20,
            max_open_files: 256,
        }
    }

    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    pub fn with_max_open_files(mut self, count: i32) -> Self {
        self.max_open_files = cmp::max(count, 1);
        self
    }
}

#[derive(Debug)]
pub(super) struct RocksDbForestStore {
    db: Arc<DB>,
}

#[derive(Debug, Error)]
pub enum ForestStoreError {
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),
    #[error("invalid node entry length: expected {expected}, found {found}")]
    BadNodeLen { expected: usize, found: usize },
    #[error("failed to deserialize leaf")]
    LeafDecode(#[from] winter_utils::DeserializationError),
    #[error("failed to decode word from storage")]
    WordDecode(#[from] WordError),
    #[error("missing column family {0}")]
    MissingColumnFamily(String),
}

impl From<ForestStoreError> for MerkleError {
    fn from(err: ForestStoreError) -> Self {
        MerkleError::Storage(err.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
struct ForestInnerNode {
    left: Word,
    right: Word,
    rc: u64,
}

impl ForestInnerNode {
    fn hash(&self) -> Word {
        Rpo256::merge(&[self.left, self.right])
    }

    fn to_bytes(&self) -> [u8; 72] {
        let mut bytes = [0u8; 72];
        let left = self.left.as_bytes();
        let right = self.right.as_bytes();
        bytes[..32].copy_from_slice(&left);
        bytes[32..64].copy_from_slice(&right);
        bytes[64..].copy_from_slice(&self.rc.to_le_bytes());
        bytes
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, ForestStoreError> {
        if bytes.len() != 72 {
            return Err(ForestStoreError::BadNodeLen { expected: 72, found: bytes.len() });
        }

        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];
        let mut rc_bytes = [0u8; 8];
        left_bytes.copy_from_slice(&bytes[..32]);
        right_bytes.copy_from_slice(&bytes[32..64]);
        rc_bytes.copy_from_slice(&bytes[64..72]);

        let left = Word::try_from(&left_bytes[..])?;
        let right = Word::try_from(&right_bytes[..])?;
        let rc = u64::from_le_bytes(rc_bytes);

        Ok(Self { left, right, rc })
    }
}

#[derive(Clone, Debug)]
pub struct IndexedPath {
    pub value: Word,
    pub path: Vec<(NodeIndex, Word)>,
}

impl RocksDbForestStore {
    pub fn open(config: RocksDbForestConfig) -> Result<Self, ForestStoreError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(config.max_open_files);

        let cache = Cache::new_lru_cache(config.cache_size);
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&cache);
        table_opts.set_bloom_filter(10.0, false);

        let mut nodes_opts = Options::default();
        nodes_opts.set_block_based_table_factory(&table_opts);

        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&table_opts);

        let mut roots_opts = Options::default();
        roots_opts.set_block_based_table_factory(&table_opts);

        let cfs = vec![
            ColumnFamilyDescriptor::new(NODES_CF, nodes_opts),
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(ROOTS_CF, roots_opts),
        ];

        let db = DB::open_cf_descriptors(&db_opts, config.path, cfs)?;
        let store = Self { db: Arc::new(db) };
        store.initialize()?;
        Ok(store)
    }

    pub fn contains_root(&self, root: Word) -> Result<bool, ForestStoreError> {
        let cf = self.cf_handle(ROOTS_CF)?;
        Ok(self.db.get_cf(cf, root.as_bytes())?.is_some())
    }

    pub fn insert_root(&self, root: Word) -> Result<(), ForestStoreError> {
        let cf = self.cf_handle(ROOTS_CF)?;
        self.db.put_cf(cf, root.as_bytes(), [])?;
        Ok(())
    }

    pub fn remove_root_entry(&self, root: Word) -> Result<(), ForestStoreError> {
        let cf = self.cf_handle(ROOTS_CF)?;
        self.db.delete_cf(cf, root.as_bytes())?;
        Ok(())
    }

    pub fn get_leaf_by_hash(&self, hash: &Word) -> Result<Option<SmtLeaf>, ForestStoreError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        match self.db.get_cf(cf, hash.as_bytes())? {
            Some(bytes) => Ok(Some(SmtLeaf::read_from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn insert_leaf(&self, hash: Word, leaf: &SmtLeaf) -> Result<(), ForestStoreError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        self.db.put_cf(cf, hash.as_bytes(), leaf.to_bytes())?;
        Ok(())
    }

    pub fn remove_leaf(&self, hash: Word) -> Result<(), ForestStoreError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        self.db.delete_cf(cf, hash.as_bytes())?;
        Ok(())
    }

    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let cf = self.cf_handle(NODES_CF).map_err(MerkleError::from)?;

        let mut hash = root;
        if self.db.get_cf(cf, hash.as_bytes()).map_err(ForestStoreError::from)?.is_none() {
            return Err(MerkleError::RootNotInStore(root));
        }

        for i in (0..index.depth()).rev() {
            let Some(node) = self.get_node_entry_cf(cf, hash).map_err(MerkleError::from)? else {
                return Err(MerkleError::NodeIndexNotFoundInStore(hash, index));
            };
            hash = if index.is_nth_bit_odd(i) { node.right } else { node.left };
        }

        Ok(hash)
    }

    pub fn get_path(&self, root: Word, index: NodeIndex) -> Result<MerkleProof, MerkleError> {
        let IndexedPath { value, path } = self.get_indexed_path(root, index)?;
        let path_iter = path.into_iter().rev().map(|(_, value)| value);
        Ok(MerkleProof::new(value, MerklePath::from_iter(path_iter)))
    }

    pub fn set_leaves(
        &self,
        root: Word,
        leaves: impl IntoIterator<Item = (NodeIndex, IndexedPath, Word)>,
    ) -> Result<Word, MerkleError> {
        let cf = self.cf_handle(NODES_CF).map_err(MerkleError::from)?;
        if self.db.get_cf(cf, root.as_bytes()).map_err(ForestStoreError::from)?.is_none() {
            return Err(MerkleError::RootNotInStore(root));
        }

        let mut nodes_by_index = Map::<NodeIndex, Word>::new();
        let mut leaves_by_index = Map::<NodeIndex, Word>::new();

        for (index, indexed_path, leaf_hash) in leaves {
            if indexed_path.value == leaf_hash {
                continue;
            }

            nodes_by_index.extend(indexed_path.path);
            leaves_by_index.insert(index, leaf_hash);
        }

        if leaves_by_index.is_empty() {
            return Ok(root);
        }

        #[allow(unused_mut)]
        let mut sorted_leaf_indices = leaves_by_index.keys().cloned().collect::<Vec<_>>();

        #[cfg(feature = "hashmaps")]
        {
            sorted_leaf_indices.sort();
        }

        nodes_by_index.extend(leaves_by_index);

        let mut ancestors: Vec<NodeIndex> = Vec::new();
        let mut last_ancestor = NodeIndex::new_unchecked(SMT_DEPTH, 0);

        for leaf_index in sorted_leaf_indices {
            let parent = leaf_index.parent();
            if parent != last_ancestor {
                last_ancestor = parent;
                ancestors.push(last_ancestor);
            }
        }

        let mut index = 0;
        while index < ancestors.len() {
            let node = ancestors[index];
            if node.is_root() {
                break;
            }
            let parent = node.parent();
            if parent != last_ancestor {
                last_ancestor = parent;
                ancestors.push(last_ancestor);
            }
            index += 1;
        }

        let mut new_nodes: Map<Word, ForestInnerNode> = Map::new();

        for index in ancestors {
            let left_index = index.left_child();
            let right_index = index.right_child();

            let left_value = *nodes_by_index
                .get(&left_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(left_index))?;
            let right_value = *nodes_by_index
                .get(&right_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(right_index))?;

            let node = ForestInnerNode {
                left: left_value,
                right: right_value,
                rc: 0,
            };
            let new_key = node.hash();
            new_nodes.insert(new_key, node);
            nodes_by_index.insert(index, new_key);
        }

        let new_root = nodes_by_index
            .get(&NodeIndex::root())
            .copied()
            .ok_or(MerkleError::NodeIndexNotFoundInStore(root, NodeIndex::root()))?;

        let mut batch = WriteBatch::default();
        self.apply_new_nodes(cf, new_root, &mut new_nodes, &mut batch)?;
        self.db.write(batch).map_err(ForestStoreError::from)?;

        Ok(new_root)
    }

    pub fn remove_roots(&self, roots: Vec<Word>) -> Result<Vec<Word>, MerkleError> {
        let cf = self.cf_handle(NODES_CF).map_err(MerkleError::from)?;
        let mut removed_leaves = Vec::new();
        let mut batch = WriteBatch::default();

        for root in roots {
            removed_leaves.extend(self.remove_node(cf, root, &mut batch)?);
        }

        self.db.write(batch).map_err(ForestStoreError::from)?;
        Ok(removed_leaves)
    }

    fn apply_new_nodes(
        &self,
        cf: &rocksdb::ColumnFamily,
        node: Word,
        new_nodes: &mut Map<Word, ForestInnerNode>,
        batch: &mut WriteBatch,
    ) -> Result<(), ForestStoreError> {
        if node == Word::empty() {
            return Ok(());
        }

        if let Some(mut current) = self.get_node_entry_cf(cf, node)? {
            current.rc += 1;
            batch.put_cf(cf, node.as_bytes(), current.to_bytes());
            return Ok(());
        }

        if let Some(mut smt_node) = new_nodes.remove(&node) {
            smt_node.rc = 1;
            batch.put_cf(cf, node.as_bytes(), smt_node.to_bytes());
            self.apply_new_nodes(cf, smt_node.left, new_nodes, batch)?;
            self.apply_new_nodes(cf, smt_node.right, new_nodes, batch)?;
        }

        Ok(())
    }

    fn remove_node(
        &self,
        cf: &rocksdb::ColumnFamily,
        node: Word,
        batch: &mut WriteBatch,
    ) -> Result<Vec<Word>, MerkleError> {
        if node == Word::empty() {
            return Ok(vec![]);
        }

        let Some(mut smt_node) = self.get_node_entry_cf(cf, node).map_err(MerkleError::from)?
        else {
            return Ok(vec![node]);
        };

        if smt_node.rc == 0 {
            return Ok(vec![]);
        }

        smt_node.rc -= 1;
        if smt_node.rc > 0 {
            batch.put_cf(cf, node.as_bytes(), smt_node.to_bytes());
            return Ok(vec![]);
        }

        batch.delete_cf(cf, node.as_bytes());
        let mut result = self.remove_node(cf, smt_node.left, batch)?;
        result.extend(self.remove_node(cf, smt_node.right, batch)?);
        Ok(result)
    }

    pub fn get_indexed_path(&self, root: Word, index: NodeIndex) -> Result<IndexedPath, MerkleError> {
        let cf = self.cf_handle(NODES_CF).map_err(MerkleError::from)?;

        let mut hash = root;
        let mut path = Vec::with_capacity(index.depth().into());

        if self.db.get_cf(cf, hash.as_bytes()).map_err(ForestStoreError::from)?.is_none() {
            return Err(MerkleError::RootNotInStore(hash));
        }

        let mut current_index = NodeIndex::root();
        for i in (0..index.depth()).rev() {
            let Some(node) = self.get_node_entry_cf(cf, hash).map_err(MerkleError::from)? else {
                return Err(MerkleError::NodeIndexNotFoundInStore(hash, index));
            };

            hash = if index.is_nth_bit_odd(i) {
                path.push((current_index.left_child(), node.left));
                current_index = current_index.right_child();
                node.right
            } else {
                path.push((current_index.right_child(), node.right));
                current_index = current_index.left_child();
                node.left
            };
        }

        Ok(IndexedPath { value: hash, path })
    }

    fn initialize(&self) -> Result<(), ForestStoreError> {
        let nodes_cf = self.cf_handle(NODES_CF)?;
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        if self.db.get_cf(nodes_cf, empty_root.as_bytes())?.is_none() {
            let mut batch = WriteBatch::default();
            for (hash, node) in empty_hashes() {
                batch.put_cf(nodes_cf, hash.as_bytes(), node.to_bytes());
            }
            self.db.write(batch)?;
        }

        if !self.contains_root(empty_root)? {
            self.insert_root(empty_root)?;
        }

        Ok(())
    }

    fn cf_handle(&self, name: &str) -> Result<&rocksdb::ColumnFamily, ForestStoreError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| ForestStoreError::MissingColumnFamily(name.to_string()))
    }

    fn get_node_entry_cf(
        &self,
        cf: &rocksdb::ColumnFamily,
        hash: Word,
    ) -> Result<Option<ForestInnerNode>, ForestStoreError> {
        Ok(self
            .db
            .get_cf(cf, hash.as_bytes())?
            .map(|bytes| ForestInnerNode::read_from_bytes(&bytes))
            .transpose()?)
    }
}

fn empty_hashes() -> impl Iterator<Item = (Word, ForestInnerNode)> {
    let subtrees = EmptySubtreeRoots::empty_hashes(SMT_DEPTH);
    subtrees
        .iter()
        .rev()
        .copied()
        .zip(subtrees.iter().rev().skip(1).copied())
        .map(|(child, parent)| (parent, ForestInnerNode { left: child, right: child, rc: 1 }))
}
