use rocksdb::*;

use super::{
    StorageResult,
    config::*,
    kvdb::{KVDB, KVDBFactory, KVDBSchemaFactory},
    rocks_kvdb::{RocksKVDB, RocksKVDBSchemaConfig},
    schema::*,
};

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
            tuning_options: &PersistentSmtStorageTuningOptions,
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

        let schema = Self::SchemaConfig {
            all_tables: ALL_TABLE_NAMES.to_vec(),
            db_opts,
            cfs,
        };
        Ok(schema)
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
    tuning_options: &PersistentSmtStorageTuningOptions,
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
