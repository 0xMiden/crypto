use std::collections::HashMap;

use fjall::{Database, KeyspaceCreateOptions};

use super::schema::*;
use crate::merkle::smt::large::storage::{
    StorageResult,
    config::*,
    fjall_kvdb::{FjallKVDB, FjallKVDBSchemaConfig},
    kvdb::{KVDB, KVDBFactory, KVDBSchemaFactory},
};

/// The maximum size of the write buffer for the metadata column family (currently 8 MiB).
const MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES: u64 = 8 << 20;

/// The maximum size of the write buffer for the leaves column family (currently 128 MiB).
const MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES: u64 = 128 << 20;

/// The maximum size of the write buffer for the subtree column families (currently 128 MiB).
const MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES: u64 = 128 << 20;

#[derive(Clone, Debug)]
pub struct FjallKVDBSchema {}

impl KVDBFactory for FjallKVDBSchema {
    type TKVDB = FjallKVDB;

    fn make(config: PersistentSmtStorageConfig) -> StorageResult<Self::TKVDB> {
        Self::TKVDB::new(config, Self::schema)
    }
}

impl KVDBSchemaFactory for FjallKVDBSchema {
    type SchemaConfig = FjallKVDBSchemaConfig;
    type SchemaConfigInput = Database;

    fn schema(
        _config: PersistentSmtStorageConfig,
        db: Database,
    ) -> StorageResult<Self::SchemaConfig> {
        _ = ALL_TABLE_NAMES;

        let keyspace_common_opts =
            || -> KeyspaceCreateOptions { KeyspaceCreateOptions::default().fsync_on_create(false) };

        let mut keyspaces = HashMap::new();
        for name in SUBTREE_CFS {
            let opts =
                keyspace_common_opts().max_memtable_size(MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES);
            let keyspace = db.keyspace(name, || opts)?;
            keyspaces.insert(name, keyspace);
        }

        {
            let opts =
                keyspace_common_opts().max_memtable_size(MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES);
            let keyspace = db.keyspace(LEAVES_CF, || opts)?;
            keyspaces.insert(LEAVES_CF, keyspace);
        }

        {
            let opts =
                keyspace_common_opts().max_memtable_size(MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES);
            let keyspace = db.keyspace(METADATA_CF, || opts)?;
            keyspaces.insert(METADATA_CF, keyspace);
        }

        let schema = Self::SchemaConfig { db, keyspaces };
        Ok(schema)
    }
}
