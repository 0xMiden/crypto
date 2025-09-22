use std::collections::VecDeque;

use crate::{
    EMPTY_WORD, Word,
    merkle::{
        EmptySubtreeRoots, InnerNode, LeafIndex, MerkleError, MerklePath, MutationSet, NodeIndex,
        NodeMutation, SMT_DEPTH, Smt, SmtLeaf, SmtProof, SparseMerklePath, smt::SparseMerkleTree,
    },
};

#[cfg(test)]
mod tests;

#[derive(thiserror::Error, Debug)]
pub enum HistoricalError {
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

use std::dbg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalOffset {
    ReversionsIdx(usize),
    Latest,
    TooAncient,
}

#[derive(Debug, Clone)]
pub struct SmtWithHistory {
    /// The tip of the chain `AccountTree`
    latest: Smt,
    /// Revererting [`MutationSet`]s in order from latest to oldest. meaning new ones are pushed
    /// via `push_front` and dropped via `pop_back`.
    /// These are the reversion mutations that would restore the previous state when applied.
    reversions: VecDeque<MutationSet<SMT_DEPTH, Word, Word>>,
}

impl SmtWithHistory {
    pub const MAX_HISTORY: usize = 33;

    pub fn new(latest: Smt) -> Self {
        Self { latest, reversions: VecDeque::new() }
    }

    pub fn cleanup(&mut self) {
        while self.reversions.len() > Self::MAX_HISTORY {
            self.reversions.pop_back();
        }
    }

    pub fn root(&self) -> Word {
        self.latest.root()
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        self.latest.open(key)
    }

    /// Delta offset into the past
    pub fn oldest(&self) -> usize {
        // assumes continuous reversions! This holds, since otherwise `apply_..` would fail much
        // earlier
        self.reversions.len()
    }

    // obtain the index on the in-memory reversions based on the _desired_ block num given the
    // latest block number.
    pub fn historical_offset(past_offset: usize) -> HistoricalOffset {
        match past_offset {
            0 => HistoricalOffset::Latest,
            1..Self::MAX_HISTORY => HistoricalOffset::ReversionsIdx(past_offset as usize - 1),
            _ => HistoricalOffset::TooAncient,
        }
    }

    /// Construct a new historical view on the account tree, if the relevant reversions are still
    /// available.
    pub fn historical_view<'a>(&'a self, past_offset: usize) -> Option<HistoricalTreeView<'a>> {
        // FIXME use a shared one per height
        match Self::historical_offset(past_offset) {
            HistoricalOffset::Latest => Some(HistoricalTreeView {
                historical_offset: 0,
                latest: &self.latest,
                reversions: (&[], &[]),
            }),
            HistoricalOffset::ReversionsIdx(idx) => {
                // The reversions are stored in order from most recent (index 0) to oldest.
                let (a, b) = self.reversions.as_slices();
                let reversions = if idx < a.len() {
                    // All needed reversions are in the first slice
                    (&a[..idx + 1], &b[..])
                } else if idx < a.len() + b.len() {
                    (&a[..], &b[(idx - a.len())..])
                } else {
                    // Not enough reversions stored
                    return None;
                };

                Some(HistoricalTreeView {
                    historical_offset: idx,
                    latest: &self.latest,
                    reversions,
                })
            },
            HistoricalOffset::TooAncient => None,
        }
    }

    pub(crate) fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        <Smt as SparseMerkleTree<SMT_DEPTH>>::key_to_leaf_index(key)
    }

    /// Adds a reversion to the _front_ (the first one to be applied to latest), but does _not_
    /// modify `self.latest`. Care must be taken to retain a coherent inner state when calling
    /// this!
    fn track_reversion(&mut self, reversion: MutationSet<SMT_DEPTH, Word, Word>) {
        self.reversions.push_front(reversion);
        self.cleanup();
    }

    /// Apply the given mutation set to the interior [`Smt`].
    ///
    /// Creates a reversion `MutationSet` to be able to reconstruct the previous state of the `Smt`
    /// on-demand and applies the delta as expected using [`Smt::apply_mutations`].
    /// We track the reversion directly instead of using an overlay abstraction.
    pub fn apply_mutations(
        &mut self,
        mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), HistoricalError> {
        let reversion = self
            .latest
            .apply_mutations_with_reversion(mutation_set)
            .map_err(HistoricalError::MerkleError)?;

        // Track the reversion directly - this is what we'll use for lookups
        self.track_reversion(reversion);
        Ok(())
    }
}

/// A historical view of the `Smt`
///
/// Pretend we were still at `block_number` of the `Smt`/`AccountTree` in a limited scope of
/// `MAX_HISTORY` entries. The entries are labelled with relative offsets, commonly a `BlockNumber`.
pub struct HistoricalTreeView<'a> {
    historical_offset: usize,
    latest: &'a Smt,
    /// The set over reversions
    ///
    /// Split into two pieces due to the internal state of `VecDeque` being two slices.
    /// Think of it as a single slice, in which the lower indices are the first reversion to apply
    /// in index ascending order to reach a state `n` in the past.
    reversions: (
        &'a [MutationSet<SMT_DEPTH, Word, Word>],
        &'a [MutationSet<SMT_DEPTH, Word, Word>],
    ),
}

impl HistoricalTreeView<'_> {
    /// An iterator for the reversion stack
    ///
    /// Traverses them in order to be applied, from 0 (the first to be applied, one step in the
    /// past) to the highest index (`MAX_HISTORY`).
    ///
    /// Returns a concrete iterator type that implements DoubleEndedIterator
    fn reversion_iter<'b>(
        &'b self,
    ) -> impl DoubleEndedIterator<Item = &'b MutationSet<SMT_DEPTH, Word, Word>> {
        self.reversions.0.iter().chain(self.reversions.1.iter())
    }

    /// Root of the historical view
    ///
    /// Either take the Root of all reversions combined with latest.
    pub fn root(&self) -> Word {
        // The first reversion in our iterator represents the changes needed to go back one step
        // Its old_root is the root AFTER applying it (i.e., the historical root we want)
        self.reversion_iter()
            .last()  // Get the last reversion to apply (furthest back in time)
            .map(|reversion| reversion.root())  // root() gives us the target state after applying this reversion
            .unwrap_or_else(|| self.latest.root())
    }

    /// Wrapper.
    pub(crate) fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        <Smt as SparseMerkleTree<SMT_DEPTH>>::key_to_leaf_index(key)
    }

    /// Lookup an inner node directly from the reversions
    ///
    /// If the node was removed, return the empty subtree root for that depth.
    fn lookup_inner_node_from_reversions(&self, node_index: NodeIndex) -> Option<InnerNode> {
        // Check reversions in reverse order (oldest to newest)
        // and use the OLDEST reversion that mentions this node
        for reversion in self.reversion_iter().rev() {
            if let Some(mutation) = reversion.node_mutations().get(&node_index) {
                match mutation {
                    NodeMutation::Removal => {
                        // Node was removed - return empty subtree root
                        let depth = node_index.depth();
                        return Some(EmptySubtreeRoots::get_inner_node(SMT_DEPTH, depth));
                    },
                    NodeMutation::Addition(inner_node) => {
                        // Node was added/modified - return the stored value
                        return Some(inner_node.clone());
                    },
                }
            }
        }
        // No mutation found in reversions
        None
    }

    /// Get the hash of an inner node, using reversions to look up historical values.
    /// If the node was removed, returns the empty subtree root hash.
    fn get_inner_node_hash(&self, index: NodeIndex) -> Word {
        // First check reversions for any mutations
        if let Some(inner_node) = self.lookup_inner_node_from_reversions(index) {
            return inner_node.hash();
        }

        // Fall back to the latest tree
        self.latest.get_node_hash(index)
    }

    // Helper function to get leaf hash at a specific index
    fn get_leaf_hash_at_index(&self, leaf_index: LeafIndex<SMT_DEPTH>) -> Word {
        // To get the historical leaf hash, we need to check if any reversion
        // would restore a key at this index to a different value

        // Check reversions first for any leaf changes at this index
        for reversion in self.reversion_iter() {
            for (key, value) in reversion.new_pairs() {
                let key_leaf_index = Self::key_to_leaf_index(key);
                if key_leaf_index == leaf_index {
                    // This reversion would restore this key to this value,
                    // which means that's what the value WAS historically
                    let leaf = if *value == EMPTY_WORD {
                        SmtLeaf::new_empty(leaf_index)
                    } else {
                        SmtLeaf::new_single(*key, *value)
                    };
                    return leaf.hash();
                }
            }
        }

        // Fall back to latest tree
        let node_index = NodeIndex::from(leaf_index);
        self.latest.get_node_hash(node_index)
    }

    /// Returns a [MerklePath] to the specified key.
    ///
    /// Mostly this is an implementation detail of [`Self::open()`].
    fn get_path(&self, key: &Word) -> MerklePath {
        let index = NodeIndex::from(Self::key_to_leaf_index(key));

        // proof indices include all siblings
        MerklePath::from_iter(index
            .proof_indices()
            // iterates from leaves towards the root
            .map(|index| self.get_node_hash(index)))
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        // Check reversions for mutations
        if let Some(inner_node) = self.lookup_inner_node_from_reversions(index) {
            return inner_node;
        }

        // Fall back to latest tree
        self.latest.get_inner_node(index)
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns [`Self::root()`]. Other hashes are retrieved by calling
    /// [`Self::get_inner_node()`] on the parent, and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root();
        }

        // We need to check reversions in reverse order (oldest to newest)
        // and use the OLDEST reversion that mentions this node
        // This gives us the value at the historical point we're interested in
        let mut found_mutation = None;
        for reversion in self.reversion_iter().rev() {
            if let Some(mutation) = reversion.node_mutations().get(&index) {
                found_mutation = Some(mutation.clone());
                break; // Use the first (oldest) mutation we find
            }
        }

        if let Some(mutation) = found_mutation {
            match mutation {
                NodeMutation::Removal => {
                    // Node was removed - return empty subtree root
                    let depth = index.depth();
                    return EmptySubtreeRoots::get_inner_node(SMT_DEPTH, depth).hash();
                },
                NodeMutation::Addition(inner_node) => {
                    // Node was added/modified - return the stored value
                    return inner_node.hash();
                },
            }
        }

        // If not found in reversions, get from parent node
        let parent = index.parent();
        let InnerNode { left, right } = self.get_inner_node(parent);

        let index_is_right = index.is_value_odd();
        if index_is_right { right } else { left }
    }

    pub fn get_value(&self, key: &Word) -> Word {
        match self.get_leaf(key) {
            SmtLeaf::Single(entry) => {
                // For single entries, return the value (second element of tuple)
                return entry.1;
            },
            SmtLeaf::Multiple(entries) => {
                // For multiple entries, find the matching key
                for entry in entries {
                    if entry.0 == *key {
                        return entry.1;
                    }
                }
            },
            SmtLeaf::Empty(_) => {},
        }
        EMPTY_WORD
    }

    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        // To get the historical leaf value, we need to check if any reversion
        // would restore this key to a different value
        // The reversions tell us what the value WAS before the change

        // Check reversions in reverse order (oldest to newest)
        // and use the OLDEST reversion that mentions this key
        for reversion in self.reversion_iter().rev() {
            // Check if this reversion contains information about this key
            for (rev_key, rev_value) in reversion.new_pairs() {
                if rev_key == key {
                    // This reversion would restore this key to rev_value,
                    // which means that's what the value WAS historically
                    let leaf_index = Self::key_to_leaf_index(key);
                    if *rev_value == EMPTY_WORD {
                        return SmtLeaf::new_empty(leaf_index);
                    } else {
                        return SmtLeaf::new_single(*rev_key, *rev_value);
                    }
                }
            }
        }

        // If no reversions mention this key, use the latest value
        self.latest.get_leaf(key)
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        let leaf = self.get_leaf(key);
        let leaf_idx = leaf.index();

        let path = SparseMerklePath::from_sized_iter(
            leaf_idx.index.proof_indices().map(|proof_idx| self.get_node_hash(proof_idx)),
        )
        .expect("By definition, we only construct SMT_DEPTH depths trees");

        SmtProof::new(path, leaf).unwrap()
    }
}
