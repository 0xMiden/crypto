//! This module contains the iterator needed by the persistent backend of the forest.

use alloc::boxed::Box;

use miden_serde_utils::Deserializable;
use rocksdb as db;

use crate::{
    Word,
    merkle::smt::{
        LineageId, SmtLeaf, TreeEntry, large_forest::backend::persistent::keys::LeafKey,
    },
};

// TYPE ALIASES
// ================================================================================================

/// The type of the underlying iterator over the database.
///
/// The type of items that it yields is not statically known, as it just provides bytes for
/// key-value pairs. Decoding these into the correct types is up to the client of the type.
pub type DBIterator<'db> = db::DBIteratorWithThreadMode<'db, super::DB>;

// ENTRIES ITERATOR
// ================================================================================================

/// An iterator over the entries for a given tree in the backend.
pub struct PersistentBackendEntriesIterator<'db> {
    /// The lineage whose leaves are being iterated over.
    pub lineage: LineageId,

    /// The iterator over all leaves in the database.
    iterator: DBIterator<'db>,

    /// State-machine tracking.
    state: PersistentBackendEntriesIteratorState,
}
impl<'db> PersistentBackendEntriesIterator<'db> {
    /// Constructs a new such iterator in the starting state.
    ///
    /// The provided `iterator` must yield items where the key decodes to a `LeafKey` and the value
    /// decodes to an `SmtLeaf`. If this is not the case, iteration will panic.
    ///
    /// For performance, this iterator should be passed a prefix iterator over the database with the
    /// correct prefix (corresponding to the provided `lineage`) set, but it will still function
    /// properly if this is not the case.
    pub fn new(lineage: LineageId, iterator: DBIterator<'db>) -> Self {
        let state = PersistentBackendEntriesIteratorState::NotInLeaf;
        Self { lineage, iterator, state }
    }
}

/// The internal state machine for the iterator.
enum PersistentBackendEntriesIteratorState {
    /// The iterator is not currently iterating over a particular leaf.
    NotInLeaf,

    /// The iterator is iterating over a particular leaf, with `leaf_entries` remaining to be
    /// yielded in that leaf.
    InLeaf {
        /// The iterator over the current leaf's entries.
        leaf_entries: Box<dyn Iterator<Item = (Word, Word)>>,
    },
}

impl<'db> Iterator for PersistentBackendEntriesIterator<'db> {
    type Item = TreeEntry;

    /// Advances the iterator and returns the next item if present.
    ///
    /// # Panics
    ///
    /// - If unable to read from the underlying database.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                PersistentBackendEntriesIteratorState::NotInLeaf => {
                    // Here we are not in a leaf of the targeted tree, so we have to see if we _can_
                    // be.
                    if let Some(entry) = self.iterator.next() {
                        let (key_bytes, value_bytes) = entry.expect("Able to read from the DB");
                        let key = LeafKey::read_from_bytes(&key_bytes)
                            .expect("Leaf key data read from disk is not corrupt");

                        // If the key isn't for the correct lineage (which can happen even with the
                        // bloom filter), we need to advance by returning to the loop.
                        if key.lineage != self.lineage {
                            continue;
                        }

                        // If the key is valid, we need to read out the leaf itself and then start
                        // iterating over that.
                        let leaf = SmtLeaf::read_from_bytes(&value_bytes)
                            .expect("Leaf data read from disk is not corrupt");
                        let mut leaf_entries = leaf.into_entries();
                        leaf_entries.sort_by_key(|(k, _)| *k);

                        // We change state to being in the leaf, and then recurse to return a value.
                        self.state = PersistentBackendEntriesIteratorState::InLeaf {
                            leaf_entries: Box::new(leaf_entries.into_iter()),
                        };
                    } else {
                        return None;
                    }
                },
                PersistentBackendEntriesIteratorState::InLeaf { leaf_entries } => {
                    if let Some((key, value)) = leaf_entries.next() {
                        // Here we have an entry in the leaf, so we simply need to return it.
                        return Some(TreeEntry { key, value });
                    } else {
                        // If we've run out of entries in the leaf itself, we need to see if there
                        // is another valid leaf. We do this by changing state and looping to use
                        // the existing logic.
                        self.state = PersistentBackendEntriesIteratorState::NotInLeaf;
                    }
                },
            }
        }
    }
}
