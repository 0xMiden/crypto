use core::cell::RefCell;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::RandomState,
    println,
    vec::Vec,
};

use crate::{
    EMPTY_WORD, Word,
    hash::rpo::Rpo256,
    merkle::{
        EmptySubtreeRoots, InnerNode, LeafIndex, MerklePath, MutationSet, NodeIndex, NodeMutation,
        SMT_DEPTH, Smt, SmtLeaf, SmtProof, SparseMerklePath, smt::SparseMerkleTree,
    },
};

mod tests;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("fail: {0}")]
pub struct HistoricalError(&'static str);

use std::dbg;

pub type InnerNodeHashCache = indexmap::IndexMap<usize, HashMap<NodeIndex, Word>, RandomState>;

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
    /// Reversion MutationSets in order from latest to oldest, meaning new ones are pushed via
    /// `push_front` and dropped via `pop_back`. Now this means the newer the smaller the
    /// index, so the index becomes a relative history offset.
    /// These are the reversion mutations that would restore the previous state when applied.
    reversions: VecDeque<MutationSet<SMT_DEPTH, Word, Word>>,

    // TODO use Arc<ReadWriteLock<InnerNodeHashCache>>
    cache: RefCell<InnerNodeHashCache>,
}

impl SmtWithHistory {
    const MAX_HISTORY: usize = 33;

    pub fn new(latest: Smt) -> Self {
        Self {
            latest,
            reversions: VecDeque::new(),
            cache: RefCell::new(Default::default()),
        }
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
        use std::dbg;
        let cache = self.cache.clone();
        match Self::historical_offset(dbg!(past_offset)) {
            HistoricalOffset::Latest => Some(HistoricalTreeView {
                historical_offset: 0,
                latest: &self.latest,
                reversions: (&[], &[]),
                cache,
            }),
            HistoricalOffset::ReversionsIdx(idx) => Some(HistoricalTreeView {
                historical_offset: idx,
                latest: &self.latest,
                reversions: {
                    dbg!(self.reversions.len());
                    let (a, b) = self.reversions.as_slices();
                    dbg!(a.len());
                    dbg!(b.len());
                    if idx < a.len() {
                        (&a[idx..], &b[..])
                    } else if idx < (a.len() + b.len()) {
                        (&[], &b[(idx - a.len())..])
                    } else if self.reversions.len() < idx {
                        // we might not have sufficient index despite the index being small enough
                        return None;
                    } else {
                        unreachable!("Index must never be out of bounds of combined length")
                    }
                },
                cache,
            }),
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
        // FIXME move the cache entries as well
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
            .map_err(|_fixme| HistoricalError("merkle error FIXME"))?;

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
    // 0 is top, nth is bottom, so if we query we query from the top
    reversions: (
        &'a [MutationSet<SMT_DEPTH, Word, Word>],
        &'a [MutationSet<SMT_DEPTH, Word, Word>],
    ),

    cache: RefCell<InnerNodeHashCache>,
}

impl HistoricalTreeView<'_> {
    /// An iterator for the reversion stacks
    fn reversion_iter<'b>(
        &'b self,
    ) -> impl Iterator<Item = &'b MutationSet<SMT_DEPTH, Word, Word>> {
        self.reversions.0.iter().chain(self.reversions.1.iter())
    }

    /// Root of all reversions combined with latest.
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

    /// Lookup an inner node directly from the reversions.
    /// If the node was removed, return the empty subtree root for that depth.
    /// This replaces the need for a separate overlay abstraction.
    fn lookup_inner_node_from_reversions(&self, node_index: NodeIndex) -> Option<InnerNode> {
        // Check each reversion to see if this node was mutated
        for reversion in self.reversion_iter() {
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

    /// Check if a node was removed in any reversion up to the given offset
    fn was_node_removed(&self, node_index: NodeIndex, up_to_offset: usize) -> bool {
        for (i, reversion) in self.reversion_iter().enumerate() {
            if i >= up_to_offset {
                break;
            }
            if let Some(NodeMutation::Removal) = reversion.node_mutations().get(&node_index) {
                return true;
            }
        }
        false
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

    // Dynamically calculate the inner node hash, using reversions directly for lookups
    fn compute_historical_node_hash(&self, index_to_compute: NodeIndex, cache_key: usize) -> Word {
        // If we already have the value cached, return it
        if let Some(cached_value) = self
            .cache
            .borrow_mut()
            .entry(cache_key)
            .or_default()
            .get(&index_to_compute)
            .copied()
        {
            println!("EARLY EXIT found cached value for: {}", index_to_compute);
            return cached_value;
        }

        // Check if this node was removed in reversions
        if let Some(inner_node) = self.lookup_inner_node_from_reversions(index_to_compute) {
            let hash = inner_node.hash();
            println!(
                "Node {} found in reversions (possibly removed), hash: {:?}",
                index_to_compute, hash
            );
            // Cache the result
            self.cache
                .borrow_mut()
                .entry(cache_key)
                .or_default()
                .insert(index_to_compute, hash);
            return hash;
        }

        // Walk towards the leaves from the given node index to find what needs to be computed
        let mut cache = self.cache.borrow_mut();
        let digest_cache = cache.entry(cache_key).or_default();

        // BFS from the provided index
        let mut compute_backlog = VecDeque::new();
        let mut q = VecDeque::new();
        let mut dedup = HashSet::new();

        q.push_back(index_to_compute);

        println!("walk down the tree");
        while let Some(current) = q.pop_front() {
            if current.depth() >= SMT_DEPTH {
                // leaves are always available
                continue;
            }
            if digest_cache.contains_key(&current) {
                println!("Key exists in cache at: {}", current);
                continue;
            }
            if !dedup.insert(current) {
                println!("Already has current");
                continue;
            }

            compute_backlog.push_back(current);

            // enqueue both children
            let left = current.left_child();
            if !digest_cache.contains_key(&left) {
                q.push_back(left);
            }
            let right = current.right_child();
            if !digest_cache.contains_key(&right) {
                q.push_back(right);
            }
            println!("processing node {current}");
        }
        drop(cache);
        println!("walk down the tree DONE");

        // Now compute from leaves to root
        while let Some(node) = compute_backlog.pop_back() {
            let mut cache = self.cache.borrow_mut();
            let digest_cache = cache.entry(cache_key).or_default();

            if node.depth() == SMT_DEPTH {
                // Leaf level - get the leaf hash
                let leaf_index = LeafIndex::<SMT_DEPTH>::new(node.value() as u64).unwrap();
                let hash = self.get_leaf_hash_at_index(leaf_index);
                digest_cache.insert(node, hash);
                println!("Retrieved LEAF at: {}", node);
            } else {
                assert!(
                    node.depth() < SMT_DEPTH,
                    "Ordering constraint always holds, leaves to root"
                );
                // Inner node - compute from children
                let left = node.left_child();
                let right = node.right_child();

                // Get child hashes, checking reversions first
                let left_hash = if let Some(inner) = self.lookup_inner_node_from_reversions(left) {
                    inner.hash()
                } else if let Some(hash) = digest_cache.get(&left).copied() {
                    println!("Found child (left) in cache at: {}", left);
                    hash
                } else if left.depth() == SMT_DEPTH {
                    // Handle leaf nodes specially
                    let leaf_index = LeafIndex::<SMT_DEPTH>::new(left.value() as u64).unwrap();
                    self.get_leaf_hash_at_index(leaf_index)
                } else {
                    println!("Fetching latest (left) at: {}", left);
                    self.latest.get_node_hash(left)
                };

                let right_hash = if let Some(inner) = self.lookup_inner_node_from_reversions(right)
                {
                    inner.hash()
                } else if let Some(hash) = digest_cache.get(&right).copied() {
                    println!("Found child (right) in cache at: {}", right);
                    hash
                } else if right.depth() == SMT_DEPTH {
                    // Handle leaf nodes specially
                    let leaf_index = LeafIndex::<SMT_DEPTH>::new(right.value() as u64).unwrap();
                    self.get_leaf_hash_at_index(leaf_index)
                } else {
                    println!("Fetching latest (right) at: {}", right.depth());
                    self.latest.get_node_hash(right)
                };

                // Merge the hashes to get parent hash
                let digest = InnerNode { left: left_hash, right: right_hash }.hash();
                digest_cache.insert(node, digest);
            }
        }

        let mut cache = self.cache.borrow_mut();
        let digest_cache = cache.entry(cache_key).or_default();
        digest_cache.get(&index_to_compute).copied().unwrap_or_else(|| {
            // If we couldn't compute it, fall back to the latest value
            println!("Warning: Could not compute historical node, falling back to latest");
            self.latest.get_node_hash(index_to_compute)
        })
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
            .map(|index| {
                println!("GET NODE HASH: {index}");
                let h = self.get_node_hash(index);
                println!("GET NODE HASH == DONE: {index}");
                h
            }))
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

        // Check if this specific node was removed in reversions
        if let Some(inner_node) = self.lookup_inner_node_from_reversions(index) {
            return inner_node.hash();
        }

        let InnerNode { left, right } = self.get_inner_node(index.parent());

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

        // Check each reversion in order - the first one that mentions this key
        // tells us what the historical value should be
        for reversion in self.reversion_iter() {
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
        let leaf_idx = dbg!(leaf.index());

        let path = SparseMerklePath::from_sized_iter(
            leaf_idx
                .index
                .proof_indices()
                .map(|proof_idx| self.get_node_hash(dbg!(proof_idx)))
                .inspect(|node_digest| {
                    dbg!(node_digest);
                }),
        )
        .expect("By definition, we only construct SMT_DEPTH depths trees");

        SmtProof::new(path, leaf).unwrap()
    }
}
