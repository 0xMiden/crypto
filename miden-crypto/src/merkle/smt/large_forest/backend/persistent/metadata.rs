//! This module contains the metadata necessary for storing and restoring the state of the persisted
//! forest.

use alloc::vec::Vec;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::merkle::smt::LineageId;

// CONSTANTS
// ================================================================================================

/// The name of the file containing the metadata
const FOREST_METADATA_FILE_NAME: &str = "forest.msgpack";

// METADATA
// ================================================================================================

/// Contains the metadata necessary to restore a persisted forest from its on-disk state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    /// The lineage identifiers and the paths at which the persisted lineage data is stored.
    ///
    /// Paths should be stored **relative to the root directory** of the backend's persisted
    /// structure to enable portability on the filesystem.
    pub lineages: Vec<(LineageId, PathBuf)>,
}

impl Metadata {
    /// Generates the full path to the file into which the metadata should be written on the
    /// filesystem.
    pub fn path(base_dir: &Path) -> PathBuf {
        base_dir.join(FOREST_METADATA_FILE_NAME)
    }

    /// Generates the full path to the backup version of the metadata file.
    pub fn backup_path(base_dir: &Path) -> PathBuf {
        base_dir.join(format!("{FOREST_METADATA_FILE_NAME}.backup"))
    }
}
