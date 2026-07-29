//! RocksDB implementation of the [`KVDB`](super::KVDB) traits.

#![allow(clippy::upper_case_acronyms)]

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{fmt, mem::ManuallyDrop, ops::Deref};

use rocksdb::{Error as RocksError, *};

#[rustfmt::skip]
use super::{
    StorageError, StorageResult,
    config::*,
    kvdb::*,
};

impl From<RocksError> for StorageError {
    fn from(e: RocksError) -> Self {
        StorageError::Backend(Box::new(e))
    }
}

#[derive(Debug, Clone)]
pub struct RocksKVDB {
    db: Arc<DB>,
    durability_mode: PersistentSmtStorageDurabilityMode,
    all_table_names: Vec<&'static str>,
}

impl RocksKVDB {
    fn write_options(&self) -> WriteOptions {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(self.durability_mode == PersistentSmtStorageDurabilityMode::Sync);
        write_opts
    }
}

pub struct RocksKVDBSchemaConfig {
    pub all_tables: Vec<&'static str>,
    pub db_opts: Options,
    pub cfs: Vec<ColumnFamilyDescriptor>,
}

impl KVDB for RocksKVDB {
    type Batch<'a> = RocksKVDBBatch<'a>;
    type SchemaConfig = RocksKVDBSchemaConfig;
    type SchemaConfigInput = ();

    fn new(
        config: PersistentSmtStorageConfig,
        schema_factory: impl FnOnce(
            PersistentSmtStorageConfig,
            (),
        ) -> StorageResult<RocksKVDBSchemaConfig>,
    ) -> StorageResult<Self> {
        let schema = schema_factory(config.clone(), ())?;

        // Open the database with our tuned CFs
        let db = DB::open_cf_descriptors(&schema.db_opts, config.path, schema.cfs)?;

        Ok(Self {
            db: Arc::new(db),
            durability_mode: config.durability_mode,
            all_table_names: schema.all_tables,
        })
    }

    /// Single-key delete outside of a batch.
    fn delete(&self, table: &RocksTable, key: &[u8]) -> StorageResult<()> {
        self.db.delete_cf(table.cf(), key).map_err(Into::into)
    }

    /// Starts a new atomic write batch.
    fn batch(&self) -> RocksKVDBBatch<'_> {
        RocksKVDBBatch {
            batch: WriteBatch::default(),
            write_opts: self.write_options(),
            db: &self.db,
        }
    }

    /// Creates a point-in-time read-only snapshot of the database.
    fn snapshot(&self) -> StorageResult<RocksKVDBSnapshot> {
        Ok(RocksKVDBSnapshot::new(Arc::clone(&self.db)))
    }

    /// Flushes all column families and syncs the WAL — durability fence.
    fn sync(&self) -> StorageResult<()> {
        let mut opts = FlushOptions::default();
        opts.set_wait(true);

        for name in &self.all_table_names {
            let cf = self.db.cf_handle(name).ok_or_else(|| {
                StorageError::Unsupported(format!("unknown column family `{name}`"))
            })?;
            self.db.flush_cf_opt(cf, &opts)?;
        }

        self.db.flush_wal(true)?;
        Ok(())
    }
}

pub struct RocksKVDBBatch<'a> {
    batch: WriteBatch,
    write_opts: WriteOptions,
    db: &'a DB,
}

impl fmt::Debug for RocksKVDBBatch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksKVDBBatch").finish_non_exhaustive()
    }
}

impl KVDBBatch for RocksKVDBBatch<'_> {
    type Table = RocksTable;

    fn put(&mut self, table: &RocksTable, key: &[u8], value: &[u8]) {
        self.batch.put_cf(table.cf(), key, value);
    }

    fn delete(&mut self, table: &RocksTable, key: &[u8]) {
        self.batch.delete_cf(table.cf(), key);
    }

    fn commit(self) -> Result<(), StorageError> {
        self.db.write_opt(self.batch, &self.write_opts).map_err(Into::into)
    }

    fn append(self, other: &Self) -> Self {
        Self {
            batch: super::rocks_kvdb_batch_append::merge_batches(self.batch, &other.batch),
            write_opts: self.write_opts,
            db: self.db,
        }
    }
}

impl KVDBReader for RocksKVDB {
    type Table = RocksTable;
    type Bytes<'a> = RocksBytes<'a>;
    type Snapshot = RocksKVDBSnapshot;

    fn table(&self, name: &str) -> StorageResult<RocksTable> {
        RocksTable::new(Arc::clone(&self.db), name)
    }

    fn get<'a>(&'a self, table: &RocksTable, key: &[u8]) -> StorageResult<Option<RocksBytes<'a>>> {
        self.db
            .get_pinned_cf(table.cf(), key)
            .map(|opt| opt.map(RocksBytes::Pinned))
            .map_err(Into::into)
    }

    /// Overrides the default loop with a native `multi_get_cf` batch read.
    fn multi_get<'a>(
        &'a self,
        table: &RocksTable,
        keys: &[&[u8]],
    ) -> StorageResult<Vec<Option<RocksBytes<'a>>>> {
        self.db
            .multi_get_cf(keys.iter().map(|k| (table.cf(), *k)))
            .into_iter()
            .map(|r| match r {
                Ok(Some(v)) => Ok(Some(RocksBytes::Owned(v.into()))),
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            })
            .collect()
    }

    fn iter<'a>(
        &'a self,
        table: RocksTable,
    ) -> impl Iterator<Item = StorageResult<(RocksBytes<'a>, RocksBytes<'a>)>> + 'a {
        let cf = table.cf();
        drop(table);
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start).map(|result| {
            result
                .map(|(k, v)| (RocksBytes::Owned(k), RocksBytes::Owned(v)))
                .map_err(Into::into)
        })
    }

    fn iter_prefix<'a>(
        &'a self,
        table: &RocksTable,
        prefix: &[u8],
    ) -> impl Iterator<Item = StorageResult<(RocksBytes<'a>, RocksBytes<'a>)>> + use<'a> {
        let cf = table.cf();
        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        self.db
            .iterator_cf_opt(cf, read_opts, IteratorMode::From(prefix, Direction::Forward))
            .map(|result| {
                result
                    .map(|(k, v)| (RocksBytes::Owned(k), RocksBytes::Owned(v)))
                    .map_err(Into::into)
            })
    }
}

/// RocksTable holds a column family handle.
///
/// The `cf` field is a reference borrowed from `_db`.
/// The lifetime is erased to `static` to shield the callers.
pub struct RocksTable {
    _db: Arc<DB>,
    cf: &'static ColumnFamily,
}

impl fmt::Debug for RocksTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksTable").finish_non_exhaustive()
    }
}

// SAFETY: the inner CF reference points into the DB owned by `_db`.
// The DB outlives the table because it is held via `Arc`.
// `DB` is itself `Send + Sync`.
// `ColumnFamily` is opaque to us but stable for the DB's lifetime,
// so sharing it across threads under that invariant is sound.
unsafe impl Send for RocksTable {}
unsafe impl Sync for RocksTable {}

impl RocksTable {
    #[inline]
    pub(super) fn cf(&self) -> &'static ColumnFamily {
        self.cf
    }

    fn new(db: Arc<DB>, name: &str) -> StorageResult<Self> {
        let cf = db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))?;

        // SAFETY: We clone Arc<DB> into RocksTable so the DB (and thus the CF pointer) outlives
        // the returned RocksTable. The CF reference is valid for the DB's lifetime.
        let cf_static: &'static ColumnFamily = unsafe { core::mem::transmute(cf) };

        Ok(Self { _db: db, cf: cf_static })
    }
}

/// Owned or borrowed byte container returned by reads.
pub enum RocksBytes<'a> {
    Pinned(DBPinnableSlice<'a>),
    Owned(Box<[u8]>),
}

impl fmt::Debug for RocksBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RocksBytes").field(&self.as_ref()).finish()
    }
}

impl Deref for RocksBytes<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for RocksBytes<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            RocksBytes::Pinned(s) => s.as_ref(),
            RocksBytes::Owned(b) => b.as_ref(),
        }
    }
}

/// RocksKVDBSnapshotInner owns a `Snapshot` together with the database it borrows from.
///
/// `Snapshot` is borrowed from the DB. Storing `Arc<DB>` beside it
/// and releasing the snapshot first in `Drop` allows the static lifetime.
struct RocksKVDBSnapshotInner {
    snapshot: ManuallyDrop<Snapshot<'static>>,
    db: Arc<DB>,
}

impl RocksKVDBSnapshotInner {
    fn new(db: Arc<DB>) -> Self {
        let snapshot = db.snapshot();

        // SAFETY: The snapshot internally stores a reference to the same `DB` allocation owned by
        // `db`. `RocksKVDBSnapshotInner` keeps that `Arc<DB>` alive and its `Drop` implementation
        // manually releases the snapshot before the `Arc<DB>` field is dropped.
        let snapshot = unsafe { core::mem::transmute::<Snapshot<'_>, Snapshot<'static>>(snapshot) };

        Self {
            snapshot: ManuallyDrop::new(snapshot),
            db,
        }
    }
}

impl Drop for RocksKVDBSnapshotInner {
    fn drop(&mut self) {
        // SAFETY: `snapshot` was placed in `ManuallyDrop` only to control field drop order. It is
        // dropped exactly once here, before `db` is dropped by Rust's normal field cleanup.
        unsafe { ManuallyDrop::drop(&mut self.snapshot) };
    }
}

#[derive(Clone)]
pub struct RocksKVDBSnapshot {
    inner: Arc<RocksKVDBSnapshotInner>,
}

impl fmt::Debug for RocksKVDBSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksKVDBSnapshot").finish_non_exhaustive()
    }
}

impl RocksKVDBSnapshot {
    pub(super) fn new(db: Arc<DB>) -> Self {
        Self {
            inner: Arc::new(RocksKVDBSnapshotInner::new(db)),
        }
    }
}

impl KVDBReader for RocksKVDBSnapshot {
    type Table = RocksTable;
    type Bytes<'a> = RocksBytes<'a>;
    type Snapshot = RocksKVDBSnapshot;

    fn table(&self, name: &str) -> StorageResult<RocksTable> {
        RocksTable::new(Arc::clone(&self.inner.db), name)
    }

    fn get<'a>(&'a self, table: &RocksTable, key: &[u8]) -> StorageResult<Option<RocksBytes<'a>>> {
        self.inner
            .snapshot
            .get_pinned_cf(table.cf(), key)
            .map(|opt| opt.map(RocksBytes::Pinned))
            .map_err(Into::into)
    }

    fn multi_get<'a>(
        &'a self,
        table: &RocksTable,
        keys: &[&[u8]],
    ) -> StorageResult<Vec<Option<RocksBytes<'a>>>> {
        self.inner
            .snapshot
            .multi_get_cf(keys.iter().map(|k| (table.cf(), *k)))
            .into_iter()
            .map(|r| match r {
                Ok(Some(v)) => Ok(Some(RocksBytes::Owned(v.into()))),
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            })
            .collect()
    }

    fn iter<'a>(
        &'a self,
        table: RocksTable,
    ) -> impl Iterator<Item = StorageResult<(RocksBytes<'a>, RocksBytes<'a>)>> + 'a {
        let cf = table.cf();
        drop(table);
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        self.inner
            .snapshot
            .iterator_cf_opt(cf, read_opts, IteratorMode::Start)
            .map(|result| {
                result
                    .map(|(k, v)| (RocksBytes::Owned(k), RocksBytes::Owned(v)))
                    .map_err(Into::into)
            })
    }

    fn iter_prefix<'a>(
        &'a self,
        table: &RocksTable,
        prefix: &[u8],
    ) -> impl Iterator<Item = StorageResult<(RocksBytes<'a>, RocksBytes<'a>)>> + use<'a> {
        let cf = table.cf();
        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        self.inner
            .snapshot
            .iterator_cf_opt(cf, read_opts, IteratorMode::From(prefix, Direction::Forward))
            .map(|result| {
                result
                    .map(|(k, v)| (RocksBytes::Owned(k), RocksBytes::Owned(v)))
                    .map_err(Into::into)
            })
    }
}
