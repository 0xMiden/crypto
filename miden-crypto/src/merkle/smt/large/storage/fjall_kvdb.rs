//! Fjall implementation of the [`KVDB`](super::KVDB) traits.

#![allow(clippy::upper_case_acronyms)]

use alloc::{boxed::Box, sync::Arc};
use core::fmt;
use std::collections::HashMap;

use fjall::{Database, KeyspaceCreateOptions, OwnedWriteBatch, Readable, Snapshot};
use lsm_tree;

use super::{StorageError, StorageResult, config::*, kvdb::*, schema::*};

impl From<fjall::Error> for StorageError {
    fn from(e: fjall::Error) -> Self {
        StorageError::Backend(Box::new(e))
    }
}

#[derive(Clone)]
pub struct FjallKVDB {
    db: Database,
    keyspaces: Arc<HashMap<&'static str, fjall::Keyspace>>,
}

impl fmt::Debug for FjallKVDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallKVDB").finish_non_exhaustive()
    }
}

impl KVDB for FjallKVDB {
    type Batch<'a> = FjallKVDBBatch<'a>;

    fn new(config: PersistentSmtStorageConfig) -> StorageResult<Self> {
        let db = Database::builder(&config.path)
            .cache_size(config.cache_size as u64)
            .max_cached_files(Some(config.max_open_files as usize))
            .fsync_on_create(false)
            .open()?;

        _ = ALL_TABLE_NAMES;

        const SUBTREE_TABLES: &[&str] = &[
            SUBTREE_16_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
        ];

        let keyspace_common_opts =
            || -> KeyspaceCreateOptions { KeyspaceCreateOptions::default().fsync_on_create(false) };

        let mut keyspaces = HashMap::new();
        for name in SUBTREE_TABLES {
            let opts = keyspace_common_opts().max_memtable_size(128 << 20);
            let keyspace = db.keyspace(name, || opts)?;
            keyspaces.insert(*name, keyspace);
        }

        {
            let opts = keyspace_common_opts().max_memtable_size(128 << 20);
            let keyspace = db.keyspace(LEAVES_CF, || opts)?;
            keyspaces.insert(LEAVES_CF, keyspace);
        }

        {
            let opts = keyspace_common_opts();
            let keyspace = db.keyspace(METADATA_CF, || opts)?;
            keyspaces.insert(METADATA_CF, keyspace);
        }

        {
            let opts = keyspace_common_opts();
            let keyspace = db.keyspace(IN_MEM_DEPTH_CF, || opts)?;
            keyspaces.insert(IN_MEM_DEPTH_CF, keyspace);
        }

        if config.durability_mode == PersistentSmtStorageDurabilityMode::Relaxed {
            lsm_tree::file::set_fsync_enabled(false);
        }

        Ok(Self { db, keyspaces: Arc::new(keyspaces) })
    }

    fn delete(&self, table: &FjallTable, key: &[u8]) -> StorageResult<()> {
        table.keyspace.remove(key).map_err(Into::into)
    }

    fn batch(&self) -> FjallKVDBBatch<'_> {
        FjallKVDBBatch { batch: self.db.batch(), _db: &self.db }
    }

    fn snapshot(&self) -> StorageResult<FjallKVDBSnapshot> {
        Ok(FjallKVDBSnapshot {
            snapshot: Arc::new(self.db.snapshot()),
            key_spaces: Arc::clone(&self.keyspaces),
        })
    }

    fn sync(&self) -> StorageResult<()> {
        // Fjall already does this on Drop
        // self.db.persist(PersistMode::SyncAll).map_err(Into::into)
        Ok(())
    }
}

pub struct FjallKVDBBatch<'a> {
    batch: OwnedWriteBatch,
    _db: &'a Database,
}

impl fmt::Debug for FjallKVDBBatch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallKVDBBatch").finish_non_exhaustive()
    }
}

impl KVDBBatch for FjallKVDBBatch<'_> {
    type Table = FjallTable;

    fn put(&mut self, table: &FjallTable, key: &[u8], value: &[u8]) {
        self.batch.insert(&table.keyspace, key, value);
    }

    fn delete(&mut self, table: &FjallTable, key: &[u8]) {
        self.batch.remove(&table.keyspace, key);
    }

    fn commit(self) -> StorageResult<()> {
        self.batch.commit().map_err(Into::into)
    }

    fn append(self, other: &Self) -> Self {
        let mut batch = self.batch;
        batch.append(&other.batch);
        Self { batch, _db: self._db }
    }
}

impl KVDBReader for FjallKVDB {
    type Table = FjallTable;
    type Bytes<'a> = fjall::UserValue;
    type Snapshot = FjallKVDBSnapshot;

    fn table(&self, name: &str) -> StorageResult<FjallTable> {
        let keyspace = self
            .keyspaces
            .get(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown keyspace `{name}`")))?
            .clone();
        Ok(FjallTable { keyspace })
    }

    fn get<'a>(&self, table: &FjallTable, key: &[u8]) -> StorageResult<Option<fjall::UserValue>> {
        table.keyspace.get(key).map_err(Into::into)
    }

    fn iter<'a>(
        &'a self,
        table: FjallTable,
    ) -> impl Iterator<Item = StorageResult<(fjall::UserValue, fjall::UserValue)>> + 'a {
        table.keyspace.iter().map(|guard| guard.into_inner().map_err(Into::into))
    }
}

/// FjallTable holds a `Keyspace` handle.
///
/// `fjall::Keyspace` is an `Arc<KeyspaceInner>` under the hood so cloning is cheap.
#[derive(Clone)]
pub struct FjallTable {
    pub(super) keyspace: fjall::Keyspace,
}

impl fmt::Debug for FjallTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallTable").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct FjallKVDBSnapshot {
    snapshot: Arc<Snapshot>,
    key_spaces: Arc<HashMap<&'static str, fjall::Keyspace>>,
}

impl fmt::Debug for FjallKVDBSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FjallKVDBSnapshot").finish_non_exhaustive()
    }
}

impl KVDBReader for FjallKVDBSnapshot {
    type Table = FjallTable;
    type Bytes<'a> = fjall::UserValue;
    type Snapshot = FjallKVDBSnapshot;

    fn table(&self, name: &str) -> StorageResult<FjallTable> {
        let keyspace = self
            .key_spaces
            .get(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown keyspace `{name}`")))?
            .clone();
        Ok(FjallTable { keyspace })
    }

    fn get<'a>(&self, table: &FjallTable, key: &[u8]) -> StorageResult<Option<fjall::UserValue>> {
        self.snapshot.get(&table.keyspace, key).map_err(Into::into)
    }

    fn iter<'a>(
        &'a self,
        table: FjallTable,
    ) -> impl Iterator<Item = StorageResult<(fjall::UserValue, fjall::UserValue)>> + 'a {
        self.snapshot
            .iter(&table.keyspace)
            .map(|guard| guard.into_inner().map_err(Into::into))
    }
}
