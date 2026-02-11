//! Contains the configuration for the persistent backend.

use std::{fs, path::PathBuf};

use super::Result;
use crate::merkle::smt::BackendError;

// CONSTANTS
// ================================================================================================

/// The default size for the database cache in bytes.
const DEFAULT_CACHE_SIZE_BYTES: usize = 2 << 30;

/// The default maximum number of files that the database engine can have open at one time.
const DEFAULT_MAX_OPEN_FILES: usize = 1 << 9;

/// The default maximum for the number of trees that the backend can perform concurrent operations
/// on.
const DEFAULT_MAX_CONCURRENT_TREES: usize = 1 << 8;

// CONFIG TYPE
// ================================================================================================

/// The basic configuration for the persistent backend.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// The path at which the database can be found.
    ///
    /// This should be a directory path that the application has read/write permissions for. The
    /// database will create multiple files in this directory as part of its operation.
    pub(super) path: PathBuf,

    /// The maximum size of the backend's block cache in bytes.
    ///
    /// This cache stores blocks that the database accesses frequently in memory to improve read
    /// performance. Larger cache sizes improve read performance but consume more memory.
    ///
    /// Defaults to [`DEFAULT_CACHE_SIZE_BYTES`].
    pub(super) cache_size_bytes: usize,

    /// The maximum number of file handles that the database engine can keep open at one time.
    ///
    /// This setting affects both memory usage and the number of FDs used by the process. Higher
    /// values can improve performance for large databases, but can increase resource usage.
    ///
    /// Defaults to [`DEFAULT_MAX_OPEN_FILES`].
    pub(super) max_open_files: usize,

    /// The maximum number of trees that the backend can perform concurrent operations on.
    ///
    /// This setting affects contention for the CPU, but does not map directly to the number of
    /// concurrent tasks as operations in the backend may shard further.
    ///
    /// Defaults to [`DEFAULT_MAX_CONCURRENT_TREES`].
    pub(super) max_concurrent_trees: usize,
}

impl Config {
    /// Constructs a new configuration object with the provided database `path` and default
    /// settings.
    ///
    /// The defaults are as follows:
    ///
    /// - `cache_size_bytes`: 2 GiB
    /// - `max_open_files`: 512
    /// - `max_concurrent_trees`: 256
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the provided `path` is not accessible to the backend, or is
    ///   not a directory.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        // The provided path must be a directory or a symlink to one, and it must be RW-accessible
        // by us if it does exist.
        if path.exists() {
            if !path.is_dir() {
                return Err(BackendError::internal_from_message(format!(
                    "The path {} exists and is not a folder",
                    path.to_string_lossy()
                )));
            }

            if fs::metadata(&path)?.permissions().readonly() {
                return Err(BackendError::internal_from_message(format!(
                    "The path {} is not writable",
                    path.to_string_lossy()
                )));
            }
        }

        Ok(Self {
            path,
            cache_size_bytes: DEFAULT_CACHE_SIZE_BYTES,
            max_open_files: DEFAULT_MAX_OPEN_FILES,
            max_concurrent_trees: DEFAULT_MAX_CONCURRENT_TREES,
        })
    }
}

// BUILDER FUNCTIONS
// ================================================================================================

/// This block contains the functions for building an appropriate configuration for the backend.
impl Config {
    /// Sets the cache size in bytes for the database cache.
    ///
    /// The block cache stores frequently-accessed data block in memory to improve read performance.
    /// Larger cache sizes generally improve read performance but consume more memory.
    ///
    /// Defaults to `2 * 1024 * 1024 * 1024` bytes, or 2 GiB.
    pub fn with_cache_size_bytes(mut self, cache_size_bytes: usize) -> Self {
        self.cache_size_bytes = cache_size_bytes;
        self
    }

    /// Sets the maximum number of files that the backend can have open simultaneously.
    ///
    /// This affects both memory usage of the backend and the number of file descriptors used by the
    /// process. Higher values improve performances for large databases, but increase resource
    /// usage.
    ///
    /// Defaults to 512 files.
    pub fn with_max_open_files(mut self, max_open_files: usize) -> Self {
        self.max_open_files = max_open_files;
        self
    }

    /// Sets the maximum number of trees in the forest that can be operated on concurrently.
    ///
    /// This setting affects contention for the CPU, but does not map directly to the number of
    /// concurrent tasks as operations in the backend may shard further.
    ///
    /// Defaults to 256 trees.
    pub fn with_max_concurrent_trees(mut self, max_concurrent_trees: usize) -> Self {
        self.max_concurrent_trees = max_concurrent_trees;
        self
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn new() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;

        assert_eq!(config.cache_size_bytes, DEFAULT_CACHE_SIZE_BYTES);
        assert_eq!(config.max_open_files, DEFAULT_MAX_OPEN_FILES);
        assert_eq!(config.max_concurrent_trees, DEFAULT_MAX_CONCURRENT_TREES);

        Ok(())
    }

    #[test]
    fn with_cache_size_bytes() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_cache_size_bytes(1024);

        assert_eq!(config.cache_size_bytes, 1024);

        Ok(())
    }

    #[test]
    fn with_max_open_files() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_max_open_files(63);

        assert_eq!(config.max_open_files, 63);

        Ok(())
    }

    #[test]
    fn with_max_concurrent_trees() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_max_concurrent_trees(3);

        assert_eq!(config.max_concurrent_trees, 3);

        Ok(())
    }
}
