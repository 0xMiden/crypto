use core::ffi::c_int;

use rocksdb as db;

use super::schema::*;
use crate::merkle::smt::large::storage::{
    StorageResult,
    config::*,
    kvdb::{KVDB, KVDBFactory, KVDBSchemaFactory},
    rocks_kvdb::{RocksKVDB, RocksKVDBSchemaConfig},
};

/// The maximum size of the write buffer for the metadata column family (currently 8 MiB).
const MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES: usize = 8 << 20;

/// The maximum size of the write buffer for the leaves column family (currently 128 MiB).
const MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES: usize = 128 << 20;

/// The maximum size of the write buffer for the subtree column families (currently 128 MiB).
const MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES: usize = 128 << 20;

/// The maximum number of write buffers to maintain per column family.
const MAX_WRITE_BUFFER_COUNT: c_int = 3;

/// The minimum number of write buffers to merge when flushing.
const MIN_WRITE_BUFFERS_TO_MERGE: c_int = 1;

/// The maximum number of write buffers to retain in memory when flushing.
const MAX_WRITE_BUFFERS_TO_RETAIN: i64 = 0;

/// The compression mode to be used for all column families where compression is enabled.
///
/// This is chosen as it has fast decompression performance, and also does not require the
/// introduction of any additional dependencies into this project.
const COMPRESSION_MODE: db::DBCompressionType = db::DBCompressionType::Lz4;

/// Trigger compaction of L0 files when there are this many or more.
const L0_FILE_COMPACTION_TRIGGER: c_int = 8;

#[derive(Clone, Debug)]
pub struct RocksKVDBSchema {}

impl KVDBFactory for RocksKVDBSchema {
    type TKVDB = RocksKVDB;

    fn make(config: PersistentSmtStorageConfig) -> StorageResult<Self::TKVDB> {
        Self::TKVDB::new(config, Self::schema)
    }
}

impl KVDBSchemaFactory for RocksKVDBSchema {
    type SchemaConfig = RocksKVDBSchemaConfig;
    type SchemaConfigInput = ();

    fn schema(
        config: PersistentSmtStorageConfig,
        _input: Self::SchemaConfigInput,
    ) -> StorageResult<Self::SchemaConfig> {
        let mut db_opts = db::Options::default();

        // We start by initially setting up the base options for the whole database.
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism(rayon::current_num_threads() as _);
        db_opts.set_max_open_files(config.max_open_files as _);
        db_opts.set_max_background_jobs(rayon::current_num_threads() as _);
        db_opts.set_max_total_wal_size(config.tuning_options.max_total_wal_size);

        // We want to share a block cache across all column families.
        let cache = db::Cache::new_lru_cache(config.cache_size);

        // Now we set up our basic options for all column families.
        let mut cf_opts = db::BlockBasedOptions::default();
        cf_opts.set_block_cache(&cache);
        cf_opts.set_bloom_filter(config.tuning_options.bloom_filter_bits_per_key.leaves, false);
        cf_opts.set_whole_key_filtering(true); // Better for point lookups.
        cf_opts.set_pin_l0_filter_and_index_blocks_in_cache(true); // Improves performance.

        // From this, we can set up the configuration for each of our column families. We start with
        // the one for metadata.
        let metadata_cf_opts = Self::build_cf_opts(
            &config,
            &cf_opts,
            MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES,
            db::DBCompressionType::None,
        );

        // We can also create the configuration for our leaves column family.
        let leaves_cf_opts = Self::build_cf_opts(
            &config,
            &cf_opts,
            MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES,
            COMPRESSION_MODE,
        );

        // Finally we create them for each of our subtree CFs.
        let subtree_cfs = SUBTREE_CFS.into_iter().map(|name| {
            db::ColumnFamilyDescriptor::new(
                name,
                Self::build_cf_opts(
                    &config,
                    &cf_opts,
                    MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES,
                    COMPRESSION_MODE,
                ),
            )
        });

        // With the column-specific configuration made, we can then simply create our database
        // options
        let mut columns = vec![
            db::ColumnFamilyDescriptor::new(METADATA_CF, metadata_cf_opts),
            db::ColumnFamilyDescriptor::new(LEAVES_CF, leaves_cf_opts),
        ];
        columns.extend(subtree_cfs);

        let schema = Self::SchemaConfig {
            all_tables: ALL_TABLE_NAMES.to_vec(),
            db_opts,
            cfs: columns,
        };
        Ok(schema)
    }
}

impl RocksKVDBSchema {
    /// Unifies the building of options for column families where most parameters are shared,
    /// customizing only the `max_write_buffer_size` and `compression_mode`.
    fn build_cf_opts(
        config: &PersistentSmtStorageConfig,
        base: &db::BlockBasedOptions,
        max_write_buffer_size: usize,
        compression_mode: db::DBCompressionType,
    ) -> db::Options {
        let mut cf_opts = db::Options::default();
        cf_opts.set_block_based_table_factory(base);
        cf_opts.set_write_buffer_size(max_write_buffer_size);
        cf_opts.set_max_write_buffer_number(MAX_WRITE_BUFFER_COUNT);
        cf_opts.set_min_write_buffer_number_to_merge(MIN_WRITE_BUFFERS_TO_MERGE);
        cf_opts.set_max_write_buffer_size_to_maintain(MAX_WRITE_BUFFERS_TO_RETAIN);
        cf_opts.set_compaction_style(db::DBCompactionStyle::Level);
        cf_opts.set_target_file_size_base(config.tuning_options.target_file_size);
        cf_opts.set_compression_type(compression_mode);
        cf_opts.set_level_zero_file_num_compaction_trigger(L0_FILE_COMPACTION_TRIGGER);

        cf_opts
    }
}
