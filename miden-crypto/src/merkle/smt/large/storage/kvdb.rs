//! Generic key-value database abstraction for SMT storage backends.

#![allow(clippy::upper_case_acronyms)]

use alloc::vec::Vec;
use core::ops::Deref;
use std::fmt::Debug;

use super::{StorageResult, config::PersistentSmtStorageConfig};

/// Read-only access to a key-value database.
/// Shared shape between a live DB and a point-in-time snapshot.
pub trait KVDBReader: Send + Sync + Debug + 'static {
    /// Backend-specific table handle.
    type Table: Send + Sync;

    /// Owned or borrowed byte container returned by reads.
    type Bytes<'a>: Deref<Target = [u8]> + Send + Sync
    where
        Self: 'a;

    type Snapshot: KVDBReader<Table = Self::Table> + 'static;

    /// Looks up a table by name.
    fn table(&self, name: &str) -> StorageResult<Self::Table>;

    /// Value lookup.
    fn get<'a>(&'a self, table: &Self::Table, key: &[u8])
    -> StorageResult<Option<Self::Bytes<'a>>>;

    /// Batched value lookups.
    /// Backends with a native multi_get support override this.
    fn multi_get<'a>(
        &'a self,
        table: &Self::Table,
        keys: &[&[u8]],
    ) -> StorageResult<Vec<Option<Self::Bytes<'a>>>> {
        keys.iter().map(|k| self.get(table, k)).collect()
    }

    /// Forward range scan over an entire table.
    fn iter<'a>(
        &'a self,
        table: Self::Table,
    ) -> impl Iterator<Item = StorageResult<(Self::Bytes<'a>, Self::Bytes<'a>)>> + 'a;

    /// Forward prefix scan over a table.
    /// Yields only key-value pairs whose key starts with `prefix`.
    fn iter_prefix<'a>(
        &'a self,
        table: &Self::Table,
        prefix: &[u8],
    ) -> impl Iterator<Item = StorageResult<(Self::Bytes<'a>, Self::Bytes<'a>)>> + use<'a, Self>;
}

/// Read + write access to a key-value database.
pub trait KVDB: KVDBReader + 'static {
    type Batch<'a>: KVDBBatch<Table = Self::Table> + 'a
    where
        Self: 'a;

    fn new(config: PersistentSmtStorageConfig) -> StorageResult<Self>
    where
        Self: Sized;

    /// Deletes a key.
    #[allow(dead_code)]
    fn delete(&self, table: &Self::Table, key: &[u8]) -> StorageResult<()>;

    /// Starts a new atomic batch.
    fn batch(&self) -> Self::Batch<'_>;

    /// Creates a point-in-time read-only snapshot of the database.
    /// Subsequent writes through `self` do not affect reads through the returned snapshot.
    fn snapshot(&self) -> StorageResult<Self::Snapshot>;

    /// Flush in-memory state and fsync to disk.
    fn sync(&self) -> StorageResult<()>;
}

/// Atomic batch of put/delete operations spanning one or more tables.
pub trait KVDBBatch {
    type Table;

    /// Stages a put.
    fn put(&mut self, table: &Self::Table, key: &[u8], value: &[u8]);

    /// Stages deletion.
    fn delete(&mut self, table: &Self::Table, key: &[u8]);

    /// Atomically applies all staged operations.
    fn commit(self) -> StorageResult<()>;

    /// Appends another batch of operations to this.
    #[allow(dead_code)]
    fn append(self, other: &Self) -> Self;
}
