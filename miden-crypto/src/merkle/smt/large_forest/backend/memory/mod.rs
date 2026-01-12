//! This module contains a non-persistent, in-memory [`Backend`] for the SMT forest. It is
//! non-parallel and is not intended to be such, allowing its use on effectively any platform where
//! this library can be built.
//!
//! # Performance

mod tests;

use alloc::{boxed::Box, vec::Vec};

use crate::{
    Map, Word,
    merkle::{
        EmptySubtreeRoots,
        smt::{
            ForestOperation, Root, SMT_DEPTH, Smt, SmtProof, VersionId,
            large_forest::{
                Backend,
                backend::{BackendError, MutationSet, Result},
                operation::{SmtForestUpdateBatch, SmtUpdateBatch},
            },
        },
    },
};
// IN-MEMORY BACKEND
// ================================================================================================

/// The in-memory backend itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryBackend {
    /// The storage for the full trees that are stored in this backend.
    ///
    /// It should never contain an entry for a root that is not the current root of its lineage.
    /// This means that if modifications are made, then it should remove the older version when it
    /// can.
    ///
    /// # Boxing
    ///
    /// In order to enable the cheap update of the root each tree is stored under, we box the trees
    /// themselves. This means that we do not risk a memcpy for the tree in the `Map::remove`
    /// followed by `Map::insert` dance.
    trees: Map<Root, Box<Smt>>,

    /// A mapping from tree roots to their corresponding versions.
    ///
    /// This map must only contain entries for each root in `trees`, and must not contain any other
    /// entries.
    versions: Map<Root, VersionId>,
}

impl InMemoryBackend {
    /// Constructs a new instance of the in-memory backend.
    pub fn new() -> Self {
        let trees = Map::default();
        let versions = Map::default();
        Self { trees, versions }
    }

    /// Updates the tree with the specified `root` using `updates` and returning the mutation set
    /// that would reverse the changes to the tree.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if operations on the merkle tree fail for any reason.
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn update_tree_from_vec(
        &mut self,
        root: Root,
        new_version: VersionId,
        updates: Vec<ForestOperation>,
    ) -> Result<MutationSet> {
        // TODO Work out what should happen to the state in the case that things fail. What can we
        //      do that is not horrendously expensive.

        // As the tree will need to be in the map under a different key, we take advantage of it
        // being a box and pop it to operate on it.
        let mut tree = if let Some(tree) = self.trees.remove(&root) {
            tree
        } else if root.value() == *EmptySubtreeRoots::entry(SMT_DEPTH, 0) {
            Box::new(Smt::new())
        } else {
            return Err(BackendError::UnknownRoot(root));
        };
        self.versions.remove(&root);

        debug_assert!(!self.trees.contains_key(&root), "Trees contained key {root}");
        debug_assert!(!self.versions.contains_key(&root), "Versions contained key {root}");

        // Given we have returned early if we can't proceed, we can simply operate on the tree
        // regardless of whether it existed before or not.
        let mutations = tree.compute_mutations(updates.into_iter().map(|o| o.into()))?;
        let reversion_set = tree.apply_mutations_with_reversion(mutations)?;

        // We make sure to take the tree we have and insert it into the trees map under its new
        // root, but also to update the versions map correctly.
        let new_root = root.update_root(tree.root());
        self.trees.insert(new_root, tree);
        self.versions.insert(new_root, new_version);

        debug_assert!(self.trees.contains_key(&new_root), "Trees did not contain key {new_root}");
        debug_assert!(
            self.versions.contains_key(&new_root),
            "Versions did not contain key {new_root}"
        );

        Ok(reversion_set)
    }
}

// BACKEND TRAIT
// ================================================================================================

impl Backend for InMemoryBackend {
    /// Returns an opening for the specified `key` in the SMT with the specified `root`, or returns
    /// [`None`] if there is no data for `key` in the tree.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn open(&self, root: Root, key: Word) -> Result<Option<SmtProof>> {
        Ok(self.trees.get(&root).map(|smt| smt.open(&key)))
    }

    /// Returns the value associated with the provided `key` in the SMT with the provided `root`, or
    /// [`None`] if no value exists for that `key` in the tree.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn get(&self, root: Root, key: Word) -> Result<Option<Word>> {
        Ok(self.trees.get(&root).map(|smt| smt.get_value(&key)))
    }

    /// Returns the version associated with the provided `root`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn version(&self, root: Root) -> Result<VersionId> {
        self.versions.get(&root).cloned().ok_or(BackendError::UnknownRoot(root))
    }

    /// Returns an iterator over all the tree roots and versions that the backend knows about.
    ///
    /// The iteration order is unspecified.
    ///
    /// # Errors
    ///
    /// Does not actually return any errors, but is required to by the method signature on the
    /// trait.
    fn versions(&self) -> Result<impl Iterator<Item = (Root, VersionId)>> {
        Ok(self.versions.iter().map(|(key, version)| (*key, *version)))
    }

    /// Performs the provided `updates` on the tree with the provided `root`, returning the mutation
    /// set that would reverse the changes to the tree.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if operations on the merkle tree fail for any reason.
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn update_tree(
        &mut self,
        root: Root,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet> {
        // TODO Work out what should happen to the state in the case that things fail. What can we
        //      do that is not horrendously expensive.
        self.update_tree_from_vec(root, new_version, updates.consume())
    }

    /// Performs the provided `updates` on the entire forest, returning the mutation
    /// sets that would reverse the changes to each tree in the forest
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if operations on the merkle tree fail for any reason.
    /// - [`BackendError::UnknownRoot`] if the provided `root` is not known by the backend.
    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<MutationSet>> {
        // TODO Work out what should happen to the state in the case that things fail. Currently
        //      this will terminate at the first error.
        updates
            .consume()
            .into_iter()
            .map(|(root, updates)| self.update_tree_from_vec(root, new_version, updates))
            .collect::<Result<Vec<_>>>()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}
