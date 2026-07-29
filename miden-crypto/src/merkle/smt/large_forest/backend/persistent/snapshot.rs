use alloc::{sync::Arc, vec::Vec};
use std::collections::HashMap;

use miden_serde_utils::{Deserializable, Serializable};

use crate::merkle::smt::large::storage::kvdb::*;

#[rustfmt::skip]
use crate::merkle::smt::large::storage::rocks_kvdb::RocksKVDBSnapshot;

use super::{
    super::{BackendError, Result},
    iterator::PersistentBackendEntriesIterator,
    keys::{LeafKey, SubtreeKey},
    schema::*,
    subtree_cf_name,
    tree_metadata::TreeMetadata,
};
use crate::{
    Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex, SparseMerklePath,
        smt::{
            BackendReader, InnerNode, LeafIndex, LineageId, SMT_DEPTH, SmtLeaf, SmtProof, Subtree,
            TreeEntry, TreeWithRoot, VersionId, full::concurrent::SUBTREE_DEPTH,
        },
    },
};

// PERSISTENT BACKEND SNAPSHOT INNER
// ================================================================================================

/// Inner state shared by all clones of a [`PersistentBackendReader`].
pub(super) struct SnapshotInner {
    kvdb_snapshot: RocksKVDBSnapshot,
    /// Point-in-time view of the lineage metadata, shared with the backend via copy-on-write.
    lineages: Arc<HashMap<LineageId, TreeMetadata>>,
}

impl core::fmt::Debug for SnapshotInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotInner").finish_non_exhaustive()
    }
}

// PERSISTENT BACKEND READER
// ================================================================================================

/// A read-only, point-in-time snapshot of a [`PersistentBackend`](super::PersistentBackend).
///
/// This type intentionally implements only [`BackendReader`], not
/// [`Backend`](crate::merkle::smt::Backend). It is returned by
/// [`Backend::reader`](crate::merkle::smt::Backend::reader) for
/// [`PersistentBackend`](super::PersistentBackend) to provide read-only access to a consistent
/// snapshot of the backend state without exposing any mutation capabilities.
///
/// All reads go through a RocksDB snapshot, so the view is frozen at the instant
/// [`Backend::reader`](crate::merkle::smt::Backend::reader) was called; concurrent writes to the
/// underlying database are invisible to this reader.
///
/// Cloning is O(1): both the snapshot and the lineage metadata are owned by the inner `Arc`.
#[derive(Clone, Debug)]
pub struct PersistentBackendReader {
    inner: Arc<SnapshotInner>,
}

impl PersistentBackendReader {
    pub(super) fn new(
        kvdb_snapshot: RocksKVDBSnapshot,
        lineages: Arc<HashMap<LineageId, TreeMetadata>>,
    ) -> Self {
        let inner = SnapshotInner { kvdb_snapshot, lineages };
        Self { inner: Arc::new(inner) }
    }

    fn load_subtree(&self, tree_key: SubtreeKey) -> Result<Option<Subtree>> {
        let table = self.inner.kvdb_snapshot.table(subtree_cf_name(tree_key.index.depth()))?;
        let key_bytes = tree_key.to_bytes();
        let result = match self.inner.kvdb_snapshot.get(&table, &key_bytes) {
            Ok(Some(bytes)) => Some(Subtree::from_vec(tree_key.index, &bytes)?),
            Ok(None) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(result)
    }

    fn load_leaf_raw(&self, key: &LeafKey) -> Result<Option<SmtLeaf>> {
        let table = self.inner.kvdb_snapshot.table(LEAVES_CF)?;
        let key_bytes = key.to_bytes();
        let leaf_bytes = self.inner.kvdb_snapshot.get(&table, &key_bytes)?;
        Ok(match leaf_bytes {
            Some(bytes) => Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?),
            None => None,
        })
    }

    fn load_leaf_for(&self, lineage: LineageId, key: Word) -> Result<Option<SmtLeaf>> {
        let key = LeafKey {
            lineage,
            index: LeafIndex::from(key).position(),
        };
        self.load_leaf_raw(&key)
    }
}

impl BackendReader for PersistentBackendReader {
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        open_proof(
            &self.inner.lineages,
            lineage,
            key,
            |l, k| self.load_leaf_for(l, k),
            |k| self.load_subtree(k),
        )
    }

    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let key = LeafKey { lineage, index: leaf_index.position() };
        Ok(self.load_leaf_raw(&key)?.unwrap_or_else(|| SmtLeaf::new_empty(leaf_index)))
    }

    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let leaf = self.load_leaf_for(lineage, key)?;
        Ok(leaf.and_then(|l| {
            let val = l.get_value(&key);
            val.and_then(|e| if e.is_empty() { None } else { Some(e) })
        }))
    }

    fn version(&self, lineage: LineageId) -> Result<VersionId> {
        let metadata =
            self.inner.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.version)
    }

    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>> {
        Ok(self.inner.lineages.keys().copied())
    }

    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>> {
        Ok(self
            .inner
            .lineages
            .iter()
            .map(|(l, m)| TreeWithRoot::new(*l, m.version, m.root_value)))
    }

    fn entry_count(&self, lineage: LineageId) -> Result<usize> {
        let metadata =
            self.inner.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.entry_count.try_into().expect("Count of entries should fit into usize"))
    }

    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let lineage_bytes = lineage.to_bytes();
        let table = self.inner.kvdb_snapshot.table(LEAVES_CF)?;
        let pfx_iterator = self.inner.kvdb_snapshot.iter_prefix(&table, &lineage_bytes);
        Ok(PersistentBackendEntriesIterator::new(lineage, pfx_iterator))
    }
}

// HELPERS
// ================================================================================================

fn compute_merkle_path(
    mut leaf_index: NodeIndex,
    subtrees: &HashMap<NodeIndex, Subtree>,
) -> SparseMerklePath {
    let mut path = Vec::with_capacity(SMT_DEPTH as usize);

    while leaf_index.depth() > 0 {
        let is_right = leaf_index.is_position_odd();
        leaf_index = leaf_index.parent();

        let root = Subtree::find_subtree_root(leaf_index);
        let subtree = &subtrees[&root];
        let InnerNode { left, right } = subtree
            .get_inner_node(leaf_index)
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, leaf_index.depth()));

        path.push(if is_right { left } else { right });
    }

    SparseMerklePath::from_sized_iter(path).expect("Always succeeds by construction")
}

pub(super) fn open_proof(
    lineages: &HashMap<LineageId, TreeMetadata>,
    lineage: LineageId,
    key: Word,
    load_leaf: impl Fn(LineageId, Word) -> Result<Option<SmtLeaf>>,
    load_subtree: impl Fn(SubtreeKey) -> Result<Option<Subtree>>,
) -> Result<SmtProof> {
    if !lineages.contains_key(&lineage) {
        return Err(BackendError::UnknownLineage(lineage));
    }

    let leaf = load_leaf(lineage, key)?.unwrap_or_else(|| SmtLeaf::new_empty(LeafIndex::from(key)));
    let leaf_index: NodeIndex = LeafIndex::from(key).into();

    // An opening needs exactly one subtree per level; collect their roots up front so we can
    // load them all before constructing the path.
    let subtree_roots = (0..SMT_DEPTH / SUBTREE_DEPTH)
        .scan(leaf_index.parent(), |cursor, _| {
            let subtree_root = Subtree::find_subtree_root(*cursor);
            *cursor = subtree_root.parent();
            Some(subtree_root)
        })
        .collect::<Vec<_>>();

    // Loading subtrees as a separate step (rather than inline during path construction)
    // exhibits better performance due to improved pipelining and branch-predictor behavior.
    let mut subtree_cache = HashMap::<NodeIndex, Subtree>::new();
    for root in subtree_roots {
        let maybe_tree = load_subtree(SubtreeKey { lineage, index: root })?;
        subtree_cache.insert(root, maybe_tree.unwrap_or_else(|| Subtree::new(root)));
    }

    let merkle_path = compute_merkle_path(leaf_index, &subtree_cache);
    Ok(SmtProof::new_unchecked(merkle_path, leaf))
}
