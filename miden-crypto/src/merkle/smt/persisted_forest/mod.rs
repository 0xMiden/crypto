use alloc::{collections::BTreeSet, vec::Vec};

use super::{
    EmptySubtreeRoots, MerkleError, NodeIndex, SmtLeaf, SmtLeafError, SmtProof, SmtProofError, Word,
};
use crate::{
    Map,
    merkle::{LeafIndex, SMT_DEPTH},
};

mod store;
pub use store::RocksDbForestConfig;
use store::RocksDbForestStore;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct PersistedSmtForest {
    store: RocksDbForestStore,
}

impl PersistedSmtForest {
    pub fn new(config: RocksDbForestConfig) -> Result<Self, MerkleError> {
        let store = RocksDbForestStore::open(config)?;
        Ok(Self { store })
    }

    pub fn insert(&mut self, root: Word, key: Word, value: Word) -> Result<Word, MerkleError> {
        self.batch_insert(root, vec![(key, value)])
    }

    pub fn batch_insert(
        &mut self,
        root: Word,
        entries: impl IntoIterator<Item = (Word, Word)> + Clone,
    ) -> Result<Word, MerkleError> {
        if !self.contains_root(root)? {
            return Err(MerkleError::RootNotInStore(root));
        }

        let indices = entries
            .clone()
            .into_iter()
            .map(|(key, _)| LeafIndex::from(key))
            .collect::<BTreeSet<_>>();

        let mut new_leaves = Map::new();
        for index in indices {
            let node_index = NodeIndex::from(index);
            let indexed_path = self.store.get_indexed_path(root, node_index)?;
            let current_hash = indexed_path.value;

            let current_leaf = self
                .store
                .get_leaf_by_hash(&current_hash)?
                .unwrap_or_else(|| SmtLeaf::new_empty(index));

            new_leaves.insert(index, (current_hash, indexed_path, current_leaf));
        }

        for (key, value) in entries {
            let index = LeafIndex::from(key);
            let (_old_hash, _indexed_path, leaf) = new_leaves.get_mut(&index).unwrap();
            leaf.insert(key, value).map_err(to_merkle_error)?;
        }

        new_leaves = new_leaves
            .into_iter()
            .filter_map(|(key, (old_hash, indexed_path, leaf))| {
                let new_hash = leaf.hash();
                if new_hash == old_hash {
                    None
                } else {
                    Some((key, (new_hash, indexed_path, leaf)))
                }
            })
            .collect();

        let new_root = self.store.set_leaves(
            root,
            new_leaves.iter().map(|(index, leaf)| (NodeIndex::from(*index), leaf.1.clone(), leaf.0)),
        )?;

        for (leaf_hash, _indexed_path, leaf) in new_leaves.into_values() {
            self.store.insert_leaf(leaf_hash, &leaf)?;
        }
        self.store.insert_root(new_root)?;

        Ok(new_root)
    }

    pub fn open(&self, root: Word, key: Word) -> Result<SmtProof, MerkleError> {
        if !self.contains_root(root)? {
            return Err(MerkleError::RootNotInStore(root));
        }

        let leaf_index = NodeIndex::from(LeafIndex::from(key));
        let proof = self.store.get_path(root, leaf_index)?;
        let path = proof.path.try_into()?;
        let leaf_hash = proof.value;

        let Some(leaf) = self.store.get_leaf_by_hash(&leaf_hash)? else {
            return Err(MerkleError::UntrackedKey(key));
        };

        SmtProof::new(path, leaf).map_err(|error| match error {
            SmtProofError::InvalidMerklePathLength(depth) => MerkleError::InvalidPathLength(depth),
        })
    }

    pub fn pop_smts(&mut self, roots: impl IntoIterator<Item = Word>) {
        if let Err(err) = self.try_pop_smts(roots) {
            panic!("failed to remove SMTs from persisted forest: {err}");
        }
    }

    pub fn try_pop_smts(
        &mut self,
        roots: impl IntoIterator<Item = Word>,
    ) -> Result<(), MerkleError> {
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        let mut to_remove = Vec::new();
        for root in roots {
            if root == empty_root {
                continue;
            }
            if self.store.contains_root(root)? {
                to_remove.push(root);
            }
        }

        if to_remove.is_empty() {
            return Ok(());
        }

        for root in &to_remove {
            self.store.remove_root_entry(*root)?;
        }

        let removed_leaves = self.store.remove_roots(to_remove)?;
        for leaf in removed_leaves {
            self.store.remove_leaf(leaf)?;
        }

        Ok(())
    }

    fn contains_root(&self, root: Word) -> Result<bool, MerkleError> {
        let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        if root == empty_root {
            return Ok(true);
        }
        self.store.contains_root(root).map_err(MerkleError::from)
    }
}

fn to_merkle_error(err: SmtLeafError) -> MerkleError {
    match err {
        SmtLeafError::TooManyLeafEntries { actual } => MerkleError::TooManyLeafEntries { actual },
        _ => unreachable!("other SmtLeafError variants should not be possible here"),
    }
}
