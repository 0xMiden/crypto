use std::collections::HashMap;

use fjall::{Database, KeyspaceCreateOptions};

use super::{
    StorageResult,
    config::*,
    fjall_kvdb::{FjallKVDB, FjallKVDBSchemaConfig},
    kvdb::{KVDB, KVDBFactory, KVDBSchemaFactory},
    schema::*,
};

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

        let schema = Self::SchemaConfig { db, keyspaces };
        Ok(schema)
    }
}
