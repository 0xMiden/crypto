//! Yields an `Smt` that can be accessed concurrently with historical views.
//!
//! ## Constraints
//!
//! * only one `Smt` shall ever be alive, multiple might blow up storage/memory
//! * concurrent reads at a historic level must be acceptable
//! * updates are relatively rare, every second~ish
//! * the historical views have a very short livespan
//!
//! ## Nomenclature in use
//!
//! When the `latest` state is updated via `apply_mutations` we call that _forward mutation set_.
//! During this process the _reversion mutation set_ is created. For efficiency we construct
//! _reversion_-type (`Reversion`) from that.
//!
//! ## Implementation
//!
//! On every call to `apply_mutations` we create new `Reversion` and track that internally.
//! We start with a bootstrap state `Smt`. For sake of brevity, `rev` is short for a `Reversion`
//! instance.
//!
//! I.e. for the follwing call sequence
//! ```text
//! # [rev[n] .. rev[1] rev[0]] Smt
//!
//! #construction
//! [] Smt # <- smt
//!
//! # apply_mtuations(fwd0)
//! [rev(fwd0)] (smt + fwd0) = [rev(fwd0)] (smt')
//!
//! # apply_mtuations(fwd1)
//! [rev(fwd0) rev(fwd1)] (smt' + fwd1) = [rev(fwd0) rev(fwd1)] (smt'')
//! #                                      [2]       [1]         [0] <- historical index
//! ```
//!
//! Now in practice we are very much interested in the key/value leaf pairs, so we cache them
//! alongside with each reversion.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, RwLock, RwLockReadGuard},
    vec::Vec,
};

use crate::{
    EMPTY_WORD, Word,
    merkle::{
        EmptySubtreeRoots, InnerNode, LeafIndex, MerkleError, MutationSet, NodeIndex, NodeMutation,
        SMT_DEPTH, Smt, SmtLeaf, SmtProof, SparseMerklePath, smt::SparseMerkleTree,
    },
};

#[cfg(test)]
mod tests;

#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
pub enum HistoricalError {
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

/// The offset enum representing the offset relative to the `latest` `Smt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalOffset {
    ReversionsIdx(usize),
    Latest,
    TooAncient,
}

/// A wrapper for a `MutationSet` that goes backwards one step
///
/// Comes with additional caching.
#[derive(Debug, Clone)]
struct HistoricalReversion {
    /// The root at this historical point
    root: Word,
    /// The mutations that were applied to reach this state (Arc'd for sharing)
    /// This is a vector to support potential batching of mutations at a single historical point
    mutations: Arc<MutationSet<SMT_DEPTH, Word, Word>>,
    /// Calculating leaves is expense, so we keep a cache, based on the leaf digest.
    precomputed_leaves: HashMap<LeafIndex<SMT_DEPTH>, SmtLeaf>,
}

impl HistoricalReversion {
    /// Note: Called after `latest` was updated with the latest mutations. The mutations passed in
    /// to the function is the inverted set.
    fn from_reversion_mutation_set(
        inner: &mut InnerState,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Self {
        let precomputed_leaves = Self::compute_leaves_for_reversion(inner, &mutations);
        Self {
            root: mutations.root(), // The root after applying this reversion
            mutations: Arc::new(mutations),
            precomputed_leaves,
        }
    }

    /// Pre-compute leaves that are being reverted (i.e., their state before the forward mutation).
    /// These cached leaves will be used when accessing historical views.
    ///
    /// The approach: for each affected leaf position, compute the full SmtLeaf
    /// based on the current state (after mutation) but with the old values from the reversion.
    fn compute_leaves_for_reversion(
        inner: &mut InnerState,
        reversion: &MutationSet<SMT_DEPTH, Word, Word>,
    ) -> HashMap<LeafIndex<SMT_DEPTH>, SmtLeaf> {
        let mut cache = HashMap::new();

        // Group all keys by their leaf index to handle multiple keys mapping to the same leaf
        let mut keys_by_leaf: HashMap<LeafIndex<SMT_DEPTH>, Vec<(Word, Word)>> = HashMap::new();

        // The reversion contains the old values in its new_pairs
        // These represent what the values were BEFORE the mutation was applied
        for (key, value) in reversion.new_pairs() {
            let leaf_index = SmtWithHistory::key_to_leaf_index(key);
            keys_by_leaf.entry(leaf_index).or_insert_with(Vec::new).push((*key, *value));
        }

        // For each affected leaf, construct the full SmtLeaf
        // FIXME this is too complicated
        for (leaf_index, old_key_values) in keys_by_leaf {
            // Get the current leaf state (after forward mutation was applied)
            // We need to get any key that maps to this leaf index to fetch the current leaf
            // TODO double check
            let Some(pre_apply) = old_key_values.get(0).map(|tup| tup.clone()) else {
                continue;
            };
            // Already the latest state with the original forward mutation set applied. The
            // reversion set does UNDO that.
            let current_leaf = inner.latest.get_leaf(&pre_apply.0);

            // Reconstruct what the leaf looked like before the mutation
            // Start with the current leaf and replace the modified values with their old values
            let historical_leaf = match current_leaf {
                SmtLeaf::Empty(_) => {
                    // If currently empty, check if we had values before
                    if old_key_values.iter().all(|(_, v)| *v == EMPTY_WORD) {
                        // All old values were empty, so the leaf was empty before
                        SmtLeaf::Empty(leaf_index)
                    } else if old_key_values.len() == 1 {
                        // Single old key-value pair
                        let (key, value) = pre_apply;
                        if value != EMPTY_WORD {
                            // The key had a non-empty value before, so it was a single entry
                            SmtLeaf::Single((key, value))
                        } else {
                            // The key had an empty value before, so the leaf was empty
                            SmtLeaf::Empty(leaf_index)
                        }
                    } else {
                        // Multiple old values - filter out any with EMPTY_WORD values
                        let entries = Vec::<(Word, Word)>::from_iter(
                            old_key_values.into_iter().filter(|(_, v)| *v != EMPTY_WORD),
                        );
                        SmtLeaf::new(entries, leaf_index)
                            .expect("consistency is given by construction")
                    }
                },
                SmtLeaf::Single((current_key, current_value)) => {
                    // Current leaf has a single entry
                    // Check if this entry was modified
                    let mut leaf_entries = vec![(current_key, current_value)];

                    // Replace with old values
                    for (old_key, old_value) in &old_key_values {
                        if *old_key == current_key {
                            // Replace the current value with the old value
                            leaf_entries[0].1 = *old_value;
                        } else if *old_value != EMPTY_WORD {
                            // This key was removed in the mutation, add it back
                            leaf_entries.push((*old_key, *old_value));
                        }
                    }

                    // Filter out empty values and construct the appropriate leaf type
                    let entries = Vec::<(Word, Word)>::from_iter(
                        leaf_entries.into_iter().filter(|(_, v)| *v != EMPTY_WORD),
                    );

                    SmtLeaf::new(entries, leaf_index).expect("consistency is always given")
                },
                SmtLeaf::Multiple(current_entries) => {
                    // Current leaf has multiple entries
                    let mut leaf_entries = current_entries.clone();

                    // Apply the old values
                    for (old_key, old_value) in &old_key_values {
                        // Find if this key exists in current entries
                        if let Some(pos) = leaf_entries.iter().position(|(k, _)| k == old_key) {
                            if *old_value != EMPTY_WORD {
                                // Update the value
                                leaf_entries[pos] = (*old_key, *old_value);
                            } else {
                                // Remove this entry (it didn't exist before)
                                leaf_entries.remove(pos);
                            }
                        } else if *old_value != EMPTY_WORD {
                            // This key was removed in the mutation, add it back
                            leaf_entries.push((*old_key, *old_value));
                        }
                    }

                    // Filter out empty values and construct the appropriate leaf type
                    let entries = Vec::<(Word, Word)>::from_iter(
                        leaf_entries.into_iter().filter(|(_, v)| *v != EMPTY_WORD),
                    );
                    SmtLeaf::new(entries, leaf_index).expect("consistency is always given")
                },
            };

            cache.insert(leaf_index, historical_leaf);
        }

        cache
    }
}

/// Internal state that is protected by RwLock for interior mutability
#[derive(Debug)]
struct InnerState {
    /// The latest state being tracked.
    latest: Smt,
    /// Stored in order from latest to oldest. New ones are pushed via `push_front`
    /// and dropped via `pop_back`.
    /// Each state contains the mutations needed to revert from current to that historical state
    history: VecDeque<Arc<HistoricalReversion>>,
}

#[derive(Debug, Clone)]
pub struct SmtWithHistory {
    inner: Arc<RwLock<InnerState>>,
}

impl SmtWithHistory {
    pub const MAX_HISTORY: usize = 33;

    pub fn new(latest: Smt) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerState { latest, history: VecDeque::new() })),
        }
    }

    fn cleanup(history: &mut VecDeque<Arc<HistoricalReversion>>) {
        while history.len() > Self::MAX_HISTORY {
            history.pop_back();
        }
    }

    pub fn history_len(&self) -> usize {
        self.inner.read().unwrap().history.len()
    }

    pub fn root(&self) -> Word {
        self.inner.read().unwrap().latest.root()
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        self.inner.read().unwrap().latest.open(key)
    }

    /// Delta offset into the past
    pub fn oldest(&self) -> usize {
        self.inner.read().unwrap().history.len()
    }

    // obtain the index on the in-memory reversions based on the _desired_ block num given the
    // latest block number.
    pub fn historical_offset(past_offset: usize) -> HistoricalOffset {
        match past_offset {
            0 => HistoricalOffset::Latest,
            1..Self::MAX_HISTORY => HistoricalOffset::ReversionsIdx(past_offset - 1),
            _ => HistoricalOffset::TooAncient,
        }
    }

    /// Construct a new historical view on the account tree, if the relevant reversions are still
    /// available. This returns a view that holds a read guard to ensure memory safety.
    pub fn historical_view(&self, past_offset: usize) -> Option<HistoricalView<'_>> {
        let guard = self.inner.read().unwrap();

        match Self::historical_offset(past_offset) {
            HistoricalOffset::Latest => Some(HistoricalView { inner: guard, reversions: vec![] }),
            HistoricalOffset::ReversionsIdx(idx) => {
                // Collect the Arc'd historical states needed for this view
                if idx < guard.history.len() {
                    let reversions: Vec<Arc<HistoricalReversion>> =
                        guard.history.iter().take(idx + 1).cloned().collect();

                    Some(HistoricalView { inner: guard, reversions })
                } else {
                    None
                }
            },
            HistoricalOffset::TooAncient => None,
        }
    }

    pub(crate) fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        <Smt as SparseMerkleTree<SMT_DEPTH>>::key_to_leaf_index(key)
    }

    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, HistoricalError> {
        let inner = self.inner.read().unwrap();
        Ok(inner.latest.compute_mutations(kv_pairs)?)
    }

    /// Apply the given forward mutation set to the interior [`Smt`].
    /// This method uses interior mutability with RwLock, ensuring only one thread can write at a
    /// time.
    ///
    /// Creates a reversion `MutationSet` to be able to reconstruct the previous state of the `Smt`
    /// on-demand and applies the forward mutations as expected using [`Smt::apply_mutations`].
    pub fn apply_mutations(
        &self,
        mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), HistoricalError> {
        let mut inner = self.inner.write().unwrap();

        // Apply forward mutations directly to the Smt (we only have one in memory)
        let reversion = inner
            .latest
            .apply_mutations_with_reversion(mutation_set)
            .map_err(HistoricalError::MerkleError)?;

        // Track the historical state with Arc for efficient sharing
        let state = HistoricalReversion::from_reversion_mutation_set(&mut inner, reversion);
        inner.history.push_front(Arc::new(state));
        Self::cleanup(&mut inner.history);

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn first_reversion(&self) -> Option<MutationSet<SMT_DEPTH, Word, Word>> {
        let inner = self.inner.read().unwrap();
        inner.history.front().map(|state| (*state.mutations).clone())
    }
}

/// A historical view of the `Smt`
///
/// Attention: Holds a `RwLockReadGuard` to ensure the underlying `Smt` from being modified while
/// the view exists.
pub struct HistoricalView<'a> {
    /// Hold onto the `latest: Smt` to ensure it doesn't change while we use the overlay.
    inner: RwLockReadGuard<'a, InnerState>,
    /// The reversions needed to reach this historical state from `latest`.
    ///
    /// `latest + [0, 1, 2, 3, 4, 5... MAX_HISTORY] -> state at[n-1] steps into the past`
    /// where `n` is implicitly encoded in the `reversions.len()`.
    reversions: Vec<Arc<HistoricalReversion>>,
}

impl<'a> HistoricalView<'a> {
    /// An iterator for the reversion stack
    ///
    /// Flattens all mutations from all historical states, to be applied in order.
    /// The order is from newest to oldest.
    fn reversion_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &MutationSet<SMT_DEPTH, Word, Word>> + '_ {
        self.reversions.iter().map(|state| state.mutations.as_ref())
    }

    /// Root of the historical view
    pub fn root(&self) -> Word {
        // If we have reversions, the last one contains the historical root we want
        self.reversions
            .last()
            .map(|state| state.root)
            .unwrap_or_else(|| self.inner.latest.root())
    }

    /// Wrapper.
    pub(crate) fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        <Smt as SparseMerkleTree<SMT_DEPTH>>::key_to_leaf_index(key)
    }

    /// Lookup an inner node directly from the reversions
    fn lookup_inner_node_from_reversions(&self, node_index: NodeIndex) -> Option<InnerNode> {
        // Check reversions in reverse order _oldest to newest_ and use the OLDEST reversion that
        // mentions this node.
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

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        // Check reversions for mutations
        if let Some(inner_node) = self.lookup_inner_node_from_reversions(index) {
            return inner_node;
        }

        // Fall back to latest tree
        self.inner.latest.get_inner_node(index)
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root();
        }

        let mut found_mutation = None;
        for reversion in self.reversion_iter().rev() {
            if let Some(mutation) = reversion.node_mutations().get(&index) {
                found_mutation = Some(mutation.clone());
                break;
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
        // Check if we have a precomputed leaf for this key in our reversions
        let leaf_index = Self::key_to_leaf_index(key);

        // Check reversions from newest to oldest for a precomputed leaf
        for reversion in self.reversions.iter().rev() {
            if let Some(leaf) = reversion.precomputed_leaves.get(&leaf_index) {
                match leaf {
                    SmtLeaf::Single(entry) => {
                        if entry.0 == *key {
                            return entry.1;
                        }
                    },
                    SmtLeaf::Multiple(entries) => {
                        for entry in entries {
                            if entry.0 == *key {
                                return entry.1;
                            }
                        }
                    },
                    SmtLeaf::Empty(_) => return EMPTY_WORD,
                }
            }
        }

        self.inner.latest.get_value(key)
    }

    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        let leaf_index = Self::key_to_leaf_index(key);

        // Check reversions from oldest to newest for the first precomputed leaf
        // This ensures we get the correct historical state at this point in time
        self.reversions
            .iter()
            .rev()
            .find_map(|reversion| reversion.precomputed_leaves.get(&leaf_index))
            .cloned()
            .unwrap_or_else(|| self.inner.latest.get_leaf(key))
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        let leaf = self.get_leaf(key);
        let leaf_idx = leaf.index();

        let path = SparseMerklePath::from_sized_iter(
            Into::<NodeIndex>::into(leaf_idx)
                .proof_indices()
                .map(|proof_idx| self.get_node_hash(proof_idx)),
        )
        .expect("By definition, we only construct SMT_DEPTH depths trees");

        SmtProof::new(path, leaf).unwrap()
    }
}
