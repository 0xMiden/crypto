//! This module contains a persistent backend for the SMT forest built on top of the existing
//! persistent backend for the Large SMT.

mod metadata;

use alloc::string::ToString;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    prelude::v1::Vec,
};

use miden_serde_utils::ByteWriter;
use rayon::prelude::*;

use super::{BackendError, Result};
use crate::merkle::smt::{
    Backend, LargeSmt, LargeSmtError, LineageId, RocksDbConfig, RocksDbStorage,
    large::StorageError, large_forest::backend::persistent::metadata::Metadata,
};
// TODO Doc all the things

// https://docs.rs/messagepack-serde/0.2.1/messagepack_serde/

// PERSISTENT BACKEND
// ================================================================================================

/// The persistent backend for the SMT forest.
#[derive(Debug)]
#[allow(dead_code)] // Temporary
pub struct PersistentBackend {
    /// The root path into which all the persisted data for this backend is stored.
    root_dir: PathBuf,

    /// The file on disk into which the forest's persistent metadata is stored.
    ///
    /// It is currently contains a [MessagePack](https://msgpack.org) blob that provides sufficient
    /// information on how to restore the forest from disk.
    forest_meta_file: File,

    /// The file on disk used as a backup for the forest's metadata in the same format as for
    /// `forest_meta_file`.
    forest_meta_file_backup: File,

    /// A mapping from the lineages in the forest to the data that the backend stores for that
    /// lineage.
    trees: HashMap<LineageId, LineageData>,
}

// CONSTRUCTION
// ================================================================================================

/// This block contains functions for the construction of the persistent backend.
impl PersistentBackend {
    /// Constructs an empty persistent backend that contains no data, but that will store its
    /// persisted data in the provided `root_dir`.
    ///
    /// If you have existing data, please use [`Self::load`] to construct your backend.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the backend cannot be started up properly.
    pub fn empty(root_dir: PathBuf) -> Result<Self> {
        // We start by preparing the storage directory for the new backend, which must be empty if
        // we are starting a new forest. Otherwise, we risk overwriting something by accident.
        std::fs::create_dir_all(&root_dir)?;
        if std::fs::read_dir(&root_dir)?.count() != 0 {
            return Err(BackendError::Unspecified(format!(
                "Target directory {root_dir:?} for the forest was not empty"
            )));
        }

        // We can then try and create the files for our metadata chunk. The backup file does not
        // need to be readable, but the main chunk does.
        let mut forest_meta_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&Metadata::path(&root_dir))?;
        let mut forest_meta_file_backup = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&Metadata::backup_path(&root_dir))?;

        // We write metadata to both files, but cannot use `persist_metadata()` as that assumes that
        // `forest_meta_file` already contains some metadata.
        let metadata = Metadata { lineages: Vec::default() };
        let mut new_meta = Vec::new();
        messagepack_serde::to_slice(&metadata, &mut new_meta)
            .map_err(BackendError::internal_from)?;
        forest_meta_file.write_all(&new_meta)?;
        forest_meta_file_backup.write_all(&new_meta)?;

        // We finally need to create our data.
        let trees = HashMap::new();

        Ok(Self {
            root_dir,
            forest_meta_file,
            forest_meta_file_backup,
            trees,
        })
    }

    /// Constructs an instance of the persistent backend, reading the data in the provided
    /// `root_dir` and using that data to start up the backend.
    ///
    /// If you do not have existing data, please use [`Self::empty`] to construct your backend.
    ///
    /// # Errors
    ///
    /// - [`BackendError::CorruptedData`] if data corruption is encountered when loading the forest
    ///   from disk.
    /// - [`BackendError::Internal`] if the backend cannot be started up properly.
    pub fn load(root_dir: PathBuf) -> Result<Self> {
        // We start by checking that the provided directory actually exists.
        if !std::fs::exists(&root_dir)? {
            return Err(BackendError::Unspecified(format!(
                "Target directory {root_dir:?} for the forest does not exist"
            )));
        }

        // The next step in loading is to read the metadata in from the filesystem, as this
        // determines how everything else is loaded.
        let init_metadata = Self::read_metadata(&root_dir)?;

        // When we have the metadata, we know that this is _probably_ a forest, but not necessarily
        // one free of corruption so we have to be careful. Next we grab handles to the two metadata
        // files, with only the main metadata file needing RW, and the backup only needing W.
        let forest_meta_file =
            OpenOptions::new().read(true).write(true).open(&Metadata::path(&root_dir))?;
        let forest_meta_file_backup =
            OpenOptions::new().write(true).open(&Metadata::path(&root_dir))?;

        // If those succeeded, then all that remains is to try and read the actual trees from disk
        // and set them up in memory. We do this in parallel as there are no data dependencies,
        // allowing us to speed up startup time for forests with lots of lineages.
        let trees: HashMap<LineageId, LineageData> = init_metadata
            .lineages
            .into_par_iter()
            .map(|(lineage_id, path)| -> Result<(LineageId, LineageData)> {
                // We start by trying to load the LargeSMT at the provided path, but that really
                // means loading its persistent backend.
                let rocksdb_backend = RocksDbStorage::open(RocksDbConfig::new(&path))?;

                // With that done, we can actually construct the tree itself.
                let tree = LargeSmt::load(rocksdb_backend)?;

                Ok((lineage_id, LineageData { path, tree }))
            })
            .collect::<Result<_>>()?;

        // At this point we have everything we need to construct the forest.
        Ok(Self {
            root_dir,
            forest_meta_file,
            forest_meta_file_backup,
            trees,
        })
    }
}

// BACKEND TRAIT
// ================================================================================================

// INTERNAL FUNCTIONALITY
// ================================================================================================

impl PersistentBackend {
    /// Reads the forest's metadata from the filesystem.
    ///
    /// # Errors
    ///
    /// - [`BackendError::CorruptedData`] if the metadata file does not contain a valid metadata
    ///   chunk.
    /// - [`BackendError::Internal`] if the metadata cannot be read from disk.
    fn read_metadata(root_dir: &Path) -> Result<Metadata> {
        // We start by trying to read the data from the filesystem.
        let path = Metadata::path(&root_dir);
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        // If that succeeds we then try to marshal it into the correct type.
        messagepack_serde::from_slice(&buf).map_err(|e| BackendError::CorruptedData(e.to_string()))
    }

    /// Persists the metadata associated with the backend to disk.
    ///
    /// Attempts to leave the state of the metadata file consistent for as long as possible,
    /// avoiding corruption of the on-disk state as much as it can.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the process of persisting the metadata to disk fails.
    fn persist_metadata(&mut self) -> Result<()> {
        // We start by preparing our backup just in case. If anything here fails, we leave the
        // current metadata untouched.
        let mut old_meta = Vec::new();
        self.forest_meta_file.read_to_end(&mut old_meta)?;
        self.forest_meta_file_backup.write_bytes(&old_meta);

        // Next we can prepare our metadata and serialize it out to bytes. We do this in memory so
        // that any errors here still leave the existing metadata untouched.
        let metadata = Metadata {
            lineages: self.trees.iter().map(|(k, v)| (*k, v.path.clone())).collect(),
        };
        let mut new_meta = Vec::new();
        messagepack_serde::to_slice(&metadata, &mut new_meta)
            .map_err(BackendError::internal_from)?;

        // Finally we have to _actually_ write out the new metadata, which is a destructive
        // operation even with a backup.
        self.forest_meta_file.set_len(0)?;
        self.forest_meta_file.write_all(&new_meta)?;

        Ok(())
    }
}

// LINEAGE DATA
// ================================================================================================

/// The data that the backend stores on each lineage.
#[derive(Debug)]
struct LineageData {
    /// The path at which the data for the full tree is being persisted to.
    ///
    /// This path should be stored **relative to the root of the forest's data directory** to
    /// enable portability of the persisted data on disk.
    pub path: PathBuf,

    /// The full tree for the latest state of the lineage.
    pub tree: LargeSmt<RocksDbStorage>,
}

// ERRORS
// ================================================================================================

/// We generically forward errors from the `LargeSmt` subsystem of this backend as internal (and
/// hence fatal) errors in the generic [`Backend`] interface.
impl From<LargeSmtError> for BackendError {
    fn from(e: LargeSmtError) -> Self {
        BackendError::internal_from(e)
    }
}

/// We generically forward IO errors as fatal errors out of the interface of the [`Backend`] as
/// internal errors.
impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::internal_from(e)
    }
}

/// We generically forward storage backend errors out of the interface for the [`Backend`] as
/// data corruption errors.
impl From<StorageError> for BackendError {
    fn from(e: StorageError) -> Self {
        BackendError::CorruptedData(e.to_string())
    }
}
