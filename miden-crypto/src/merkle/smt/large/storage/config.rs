use std::path::PathBuf;

/// Configuration for RocksDB storage used by the Sparse Merkle Tree implementation.
///
/// This struct contains the essential configuration parameters needed to initialize
/// and optimize RocksDB for SMT storage operations. It provides sensible defaults
/// while allowing customization for specific performance requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbConfig {
    /// The filesystem path where the RocksDB database will be stored.
    ///
    /// This should be a directory path that the application has read/write permissions for.
    /// The database will create multiple files in this directory to store data, logs, and
    /// metadata.
    pub(crate) path: PathBuf,

    /// The size of the RocksDB block cache in bytes.
    ///
    /// This cache stores frequently accessed data blocks in memory to improve read performance.
    /// Larger cache sizes generally improve read performance but consume more memory.
    /// Default: 1GB (1 << 30 bytes)
    pub(crate) cache_size: usize,

    /// The maximum number of files that RocksDB can have open simultaneously.
    ///
    /// This setting affects both memory usage and the number of file descriptors used by the
    /// process. Higher values may improve performance for databases with many SST files but
    /// increase resource usage. Default: 512 files
    pub(crate) max_open_files: i32,

    /// Optional per-DB write-buffer manager shared by this DB's column families.
    pub(crate) write_buffer_manager: Option<RocksDbWriteBufferManagerBudget>,

    /// Tunable RocksDB profile values.
    pub(crate) tuning_options: RocksDbTuningOptions,

    /// Write durability mode for RocksDB write operations.
    pub(crate) durability_mode: RocksDbDurabilityMode,
}

const DEFAULT_CACHE_SIZE: usize = 1 << 30;
const DEFAULT_MAX_OPEN_FILES: i32 = 512;
const DEFAULT_BLOCK_SIZE: usize = 16 << 10;
const DEFAULT_MAX_TOTAL_WAL_SIZE: u64 = 512 * 1024 * 1024;
const DEFAULT_BLOOM_FILTER_BITS_PER_KEY: f64 = 10.0;

impl RocksDbConfig {
    /// Creates a new RocksDbConfig with the given database path and default settings.
    ///
    /// # Arguments
    /// * `path` - The filesystem path where the RocksDB database will be stored. This can be any
    ///   type that converts into a `PathBuf`.
    ///
    /// # Default Settings
    /// * `cache_size`: 1GB (1,073,741,824 bytes)
    /// * `max_open_files`: 512
    /// * `write_buffer_manager`: disabled
    /// * `tuning_options`: [`RocksDbTuningOptions::default()`]
    /// * `durability_mode`: [`RocksDbDurabilityMode::Relaxed`]
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database");
    /// ```
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            cache_size: DEFAULT_CACHE_SIZE,
            max_open_files: DEFAULT_MAX_OPEN_FILES,
            write_buffer_manager: None,
            tuning_options: RocksDbTuningOptions::default(),
            durability_mode: RocksDbDurabilityMode::default(),
        }
    }

    /// Sets the block cache size for RocksDB.
    ///
    /// The block cache stores frequently accessed data blocks in memory to improve read
    /// performance. Larger cache sizes generally improve read performance but consume more
    /// memory.
    ///
    /// # Arguments
    /// * `size` - The cache size in bytes.
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database")
    ///     .with_cache_size(2 * 1024 * 1024 * 1024); // 2GB cache
    /// ```
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Sets the RocksDB memory budget for this database instance.
    ///
    /// This controls the block cache size and optional write-buffer manager created by
    /// [`RocksDbStorage::open`] for one DB and its column families. It is not a process-wide
    /// budget across multiple RocksDB instances.
    #[must_use]
    pub fn with_memory_budget(mut self, memory_budget: RocksDbMemoryBudget) -> Self {
        let RocksDbMemoryBudget { block_cache_size, write_buffer_manager } = memory_budget;
        self.cache_size = block_cache_size;
        self.write_buffer_manager = write_buffer_manager;
        self
    }

    /// Sets the maximum number of files that RocksDB can have open simultaneously.
    ///
    /// This setting affects both memory usage and the number of file descriptors used by the
    /// process. Higher values may improve performance for databases with many SST files but
    /// increase resource usage.
    ///
    /// # Arguments
    /// * `count` - The maximum number of open files. Must be positive.
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database")
    ///     .with_max_open_files(1024); // Allow up to 1024 open files
    /// ```
    pub fn with_max_open_files(mut self, count: i32) -> Self {
        self.max_open_files = count;
        self
    }

    /// Sets the RocksDB tuning options.
    #[must_use]
    pub fn with_tuning_options(mut self, tuning_options: RocksDbTuningOptions) -> Self {
        self.tuning_options = tuning_options;
        self
    }

    /// Sets the RocksDB write durability mode.
    ///
    /// The default is [`RocksDbDurabilityMode::Relaxed`], matching RocksDB's default non-sync
    /// writes.
    #[must_use]
    pub fn with_durability_mode(mut self, durability_mode: RocksDbDurabilityMode) -> Self {
        self.durability_mode = durability_mode;
        self
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum RocksDbDurabilityMode {
    #[default]
    Relaxed,
    Sync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbMemoryBudget {
    /// Block cache size for one RocksDB instance.
    pub block_cache_size: usize,
    /// Optional write-buffer manager for one RocksDB instance.
    pub write_buffer_manager: Option<RocksDbWriteBufferManagerBudget>,
}

impl Default for RocksDbMemoryBudget {
    fn default() -> Self {
        Self {
            block_cache_size: DEFAULT_CACHE_SIZE,
            write_buffer_manager: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbWriteBufferManagerBudget {
    pub buffer_size: usize,
    pub allow_stall: bool,
    pub charge_to_block_cache: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbTuningOptions {
    pub block_size: usize,
    pub max_total_wal_size: u64,
    pub bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey,
}

impl Default for RocksDbTuningOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            max_total_wal_size: DEFAULT_MAX_TOTAL_WAL_SIZE,
            bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbBloomFilterBitsPerKey {
    pub leaves: f64,
    pub in_mem_depth: f64,
    pub subtree_16: f64,
    pub subtree_24: f64,
    pub subtree_32: f64,
    pub subtree_40: f64,
    pub subtree_48: f64,
    pub subtree_56: f64,
}

impl Default for RocksDbBloomFilterBitsPerKey {
    fn default() -> Self {
        Self {
            leaves: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            in_mem_depth: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_16: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_24: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_32: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_40: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_48: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_56: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = RocksDbConfig::new(dir.path());

        assert_eq!(config.cache_size, DEFAULT_CACHE_SIZE);
        assert_eq!(config.max_open_files, DEFAULT_MAX_OPEN_FILES);
        assert_eq!(config.durability_mode, RocksDbDurabilityMode::Relaxed);
        assert_eq!(config.write_buffer_manager, None);
        assert_eq!(config.tuning_options, RocksDbTuningOptions::default());
    }

    #[test]
    fn config_defaults_to_relaxed_durability() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(RocksDbConfig::new(dir.path()).durability_mode, RocksDbDurabilityMode::Relaxed);
    }

    #[test]
    fn config_builders_update_independent_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let memory_budget = RocksDbMemoryBudget {
            block_cache_size: 512 << 20,
            write_buffer_manager: Some(RocksDbWriteBufferManagerBudget {
                buffer_size: 64 << 20,
                allow_stall: true,
                charge_to_block_cache: true,
            }),
        };
        let tuning_options = RocksDbTuningOptions {
            block_size: 8 << 10,
            max_total_wal_size: 2 << 30,
            bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey {
                leaves: 11.0,
                in_mem_depth: 12.0,
                subtree_16: 9.0,
                subtree_24: 13.0,
                subtree_32: 14.0,
                subtree_40: 15.0,
                subtree_48: 16.0,
                subtree_56: 17.0,
            },
        };

        let config = RocksDbConfig::new(dir.path())
            .with_memory_budget(memory_budget)
            .with_max_open_files(1024)
            .with_tuning_options(tuning_options.clone())
            .with_durability_mode(RocksDbDurabilityMode::Sync);

        assert_eq!(
            config,
            RocksDbConfig {
                path: dir.path().to_path_buf(),
                cache_size: 512 << 20,
                max_open_files: 1024,
                write_buffer_manager: memory_budget.write_buffer_manager,
                tuning_options,
                durability_mode: RocksDbDurabilityMode::Sync,
            }
        );
    }
}
