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
    schema::*,
};

impl From<RocksError> for StorageError {
    fn from(e: RocksError) -> Self {
        StorageError::Backend(Box::new(e))
    }
}

#[derive(Debug, Clone)]
pub struct RocksKVDB {
    pub(super) db: Arc<DB>,
    pub(super) durability_mode: RocksDbDurabilityMode,
}

impl RocksKVDB {
    fn write_options(&self) -> WriteOptions {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(self.durability_mode == RocksDbDurabilityMode::Sync);
        write_opts
    }
}

impl KVDB for RocksKVDB {
    type Batch<'a> = RocksKVDBBatch<'a>;

    fn new(config: RocksDbConfig) -> StorageResult<Self> {
        let tuning_options = &config.tuning_options;

        // Base DB options
        let mut db_opts = Options::default();
        // Create DB if it doesn't exist
        db_opts.create_if_missing(true);
        // Auto-create missing column families
        db_opts.create_missing_column_families(true);
        // Tune compaction threads to match CPU cores
        db_opts.increase_parallelism(rayon::current_num_threads() as i32);
        // Limit the number of open file handles
        db_opts.set_max_open_files(config.max_open_files);
        // Parallelize flush/compaction up to CPU count
        db_opts.set_max_background_jobs(rayon::current_num_threads() as i32);
        // Maximum WAL size
        db_opts.set_max_total_wal_size(tuning_options.max_total_wal_size);

        // Cache and optional write-buffer manager are shared across this DB's column families.
        let cache = Cache::new_lru_cache(config.cache_size);
        let write_buffer_manager = config.write_buffer_manager.as_ref().map(|budget| {
            if budget.charge_to_block_cache {
                WriteBufferManager::new_write_buffer_manager_with_cache(
                    budget.buffer_size,
                    budget.allow_stall,
                    cache.clone(),
                )
            } else {
                WriteBufferManager::new_write_buffer_manager(budget.buffer_size, budget.allow_stall)
            }
        });

        // Common table options for bloom filtering and cache
        let mut table_opts = BlockBasedOptions::default();
        configure_block_table_options(
            &mut table_opts,
            &cache,
            tuning_options,
            tuning_options.bloom_filter_bits_per_key.leaves,
        );

        // Column family for leaves
        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&table_opts);
        configure_smt_cf_options(&mut leaves_opts);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            db_opts.set_write_buffer_manager(wbm);
            leaves_opts.set_write_buffer_manager(wbm);
        }

        // Helper to build subtree CF options with the tuned block-table profile
        #[expect(clippy::items_after_statements)]
        fn subtree_cf(
            cache: &Cache,
            tuning_options: &RocksDbTuningOptions,
            bloom_filter_bits: f64,
            write_buffer_manager: Option<&WriteBufferManager>,
        ) -> Options {
            let mut table_opts = BlockBasedOptions::default();
            configure_block_table_options(
                &mut table_opts,
                cache,
                tuning_options,
                bloom_filter_bits,
            );

            let mut opts = Options::default();
            opts.set_block_based_table_factory(&table_opts);
            configure_smt_cf_options(&mut opts);
            if let Some(wbm) = write_buffer_manager {
                opts.set_write_buffer_manager(wbm);
            }
            opts
        }

        // In-memory-depth cache column family (uses its own bloom filter setting)
        let mut in_mem_depth_table_opts = BlockBasedOptions::default();
        configure_block_table_options(
            &mut in_mem_depth_table_opts,
            &cache,
            tuning_options,
            tuning_options.bloom_filter_bits_per_key.in_mem_depth,
        );

        let mut in_mem_depth_opts = Options::default();
        in_mem_depth_opts.set_compression_type(DBCompressionType::Lz4);
        in_mem_depth_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        // Enable the bottommost compression setting; selecting ZSTD alone is not enough.
        in_mem_depth_opts
            .set_bottommost_zstd_max_train_bytes(DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES, true);
        in_mem_depth_opts.set_block_based_table_factory(&in_mem_depth_table_opts);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            in_mem_depth_opts.set_write_buffer_manager(wbm);
        }

        // Metadata CF with no compression
        let mut metadata_opts = Options::default();
        metadata_opts.set_compression_type(DBCompressionType::None);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            metadata_opts.set_write_buffer_manager(wbm);
        }

        let bloom = &tuning_options.bloom_filter_bits_per_key;

        // Define column families with tailored options
        let cfs = vec![
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(
                SUBTREE_16_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_16, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_24_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_24, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_32_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_32, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_40_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_40, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_48_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_48, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_56_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_56, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(METADATA_CF, metadata_opts),
            ColumnFamilyDescriptor::new(IN_MEM_DEPTH_CF, in_mem_depth_opts),
        ];

        // Open the database with our tuned CFs
        let db = DB::open_cf_descriptors(&db_opts, config.path, cfs)?;

        Ok(Self {
            db: Arc::new(db),
            durability_mode: config.durability_mode,
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

        for name in [
            LEAVES_CF,
            SUBTREE_16_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
            METADATA_CF,
            IN_MEM_DEPTH_CF,
        ] {
            let cf = self.db.cf_handle(name).ok_or_else(|| {
                StorageError::Unsupported(format!("unknown column family `{name}`"))
            })?;
            self.db.flush_cf_opt(cf, &opts)?;
        }

        self.db.flush_wal(true)?;
        Ok(())
    }
}

const DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES: i32 = 1 << 20;

fn configure_smt_cf_options(opts: &mut Options) {
    // 128 MB memtable
    opts.set_write_buffer_size(128 << 20);
    // Allow up to 3 memtables
    opts.set_max_write_buffer_number(3);
    opts.set_min_write_buffer_number_to_merge(1);
    // Do not retain flushed memtables in memory
    opts.set_max_write_buffer_size_to_maintain(0);
    // Use level-based compaction
    opts.set_compaction_style(DBCompactionStyle::Level);
    // 512 MB target file size
    opts.set_target_file_size_base(512 << 20);
    opts.set_target_file_size_multiplier(2);
    // LZ4 compression for active files, ZSTD for bottommost files
    opts.set_compression_type(DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(DBCompressionType::Zstd);
    // Enable the bottommost compression setting; selecting ZSTD alone is not enough.
    opts.set_bottommost_zstd_max_train_bytes(DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES, true);
    // Set level-based compaction parameters
    opts.set_level_zero_file_num_compaction_trigger(8);
}

fn configure_block_table_options(
    table_opts: &mut BlockBasedOptions,
    cache: &Cache,
    tuning_options: &RocksDbTuningOptions,
    bloom_bits_per_key: f64,
) {
    // Keep all block-based column families on the same cache and metadata policy.
    table_opts.set_block_cache(cache);
    table_opts.set_cache_index_and_filter_blocks(true);
    table_opts.set_bloom_filter(bloom_bits_per_key, false);
    table_opts.set_block_size(tuning_options.block_size);
    table_opts.set_whole_key_filtering(true);
    table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
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
}
