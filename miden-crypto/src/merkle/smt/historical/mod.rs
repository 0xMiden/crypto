// TODO: avoid all mutable borrows, it's needed due to cache, but we should be able to share the
// cache over multiple instances for a single one

use core::cell::RefCell;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    println,
    vec::Vec,
};

use crate::{
    EMPTY_WORD, Word,
    hash::rpo::Rpo256,
    merkle::{
        EmptySubtreeRoots, InnerNode, LeafIndex, MerklePath, MutationSet, NodeIndex, SMT_DEPTH,
        Smt, SmtLeaf, SmtProof, SparseMerklePath, smt::SparseMerkleTree,
    },
};

mod tests;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("fail: {0}")]
pub struct OverlayError(&'static str);

// essentially a MutationSet<SMT_DEPTH, Word, Word>;
#[derive(Debug, Clone)]
pub struct Overlay {
    old_root: Word,
    new_root: Word,
    // key to SmtLeaf (the hash of that is the value, I think)
    mutated: HashMap<Word, SmtLeaf>,

    // a lookup to see which intermediate nodes must be recalculated
    poisoned_tree_leaves: Vec<LeafIndex<SMT_DEPTH>>,
}

use std::dbg;

impl Overlay {
    // XXX scales linearly with `poisoned_tree_leaves`, but its all int-ops, so should be fairly
    // fast
    fn is_part_of_poisoned_tree(&self, node_index: NodeIndex) -> bool {
        if node_index.depth() == 0 {
            return true;
        }
        for &poisoned_tree_leaf in self.poisoned_tree_leaves.iter() {
            let mut poisoned_leaf_ancestor = NodeIndex::from(poisoned_tree_leaf);
            assert!(dbg!(poisoned_leaf_ancestor.depth()) >= dbg!(node_index.depth()));
            poisoned_leaf_ancestor.move_up_to(node_index.depth());
            if poisoned_leaf_ancestor == node_index {
                return true;
            }
        }
        false
    }
}

impl Overlay {
    /// Create the inversion of the given mutation
    pub fn walkback(
        current: &Smt,
        set: &MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<Self, OverlayError> {
        let mut inverse_mutations = HashMap::new();

        for (key, _) in set.new_pairs() {
            inverse_mutations.insert(*key, current.get_leaf(key));
        }

        let poisoned_tree_leaves =
            Vec::from_iter(inverse_mutations.values().map(|leaf| leaf.index()));

        // Create and return the inverse mutation set
        Ok(Overlay {
            new_root: set.old_root(),
            old_root: set.root(),
            mutated: inverse_mutations,
            poisoned_tree_leaves,
        })
    }

    /// Root _pre_ applying the overlay
    pub fn root(&self) -> Word {
        self.new_root
    }

    /// Root _post_ applying the overlay
    pub fn old_root(&self) -> Word {
        self.old_root
    }
}

// impl From<MutationSet<SMT_DEPTH, Word, Word>> for Overlay {
//     fn from(value: MutationSet<SMT_DEPTH, Word, Word>) -> Self {
//         let mutated = HashMap::from_iter(value.new_pairs().map(|(key, _mutation)| {
//             (key, )
//         }));
//         Self {
//             old_root: value.old_root(),
//             new_root: value.root(),
//             mutated,
//         }
//     }
// }

pub type InnerNodeHashCache = indexmap::IndexMap<usize, HashMap<NodeIndex, Word>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalOffset {
    OverlayIdx(usize),
    Latest,
    TooAncient,
    FutureBlock,
}

#[derive(Debug, Clone)]
pub struct SmtWithOverlays {
    /// The tip of the chain `AccountTree`
    latest: Smt,
    /// Overlays in order from latest to newest, meaning new ones are pushed via `push_front` and
    /// dropped via `pop_back`. Now this means the newer the smaller the index, so the index
    /// becomes a relative history offset.
    overlays: VecDeque<Overlay>,

    // TODO use Arc<ReadWriteLock<InnerNodeHashCache>>
    cache: RefCell<InnerNodeHashCache>,
}

impl SmtWithOverlays {
    const MAX_OVERLAYS: usize = 33;

    pub fn new(latest: Smt) -> Self {
        Self {
            latest,
            overlays: VecDeque::new(),
            cache: RefCell::new(Default::default()),
        }
    }

    pub fn cleanup(&mut self) {
        while self.overlays.len() > Self::MAX_OVERLAYS {
            self.overlays.pop_back();
        }
    }

    pub fn root(&self) -> Word {
        self.latest.root()
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        self.latest.open(key)
    }

    /// Delta offset into the pat
    pub fn oldest(&self) -> usize {
        // assumes continues overlays! This holds, since otherwise `apply_..` would fail much
        // earlier
        self.overlays.len()
    }

    // obtain the index on the in-memory overlays based on the _desired_ block num given the latest
    // block number.
    pub fn overlay_idx(past_offset: usize) -> HistoricalOffset {
        match past_offset {
            0 => HistoricalOffset::Latest,
            1..Self::MAX_OVERLAYS => HistoricalOffset::OverlayIdx(past_offset as usize - 1),
            _ => HistoricalOffset::TooAncient,
        }
    }

    /// Construct a new historical view on the account tree, if the relevant overlays are still
    /// available.
    pub fn historical_view<'a>(&'a self, past_offset: usize) -> Option<HistoricalTreeView<'a>> {
        // FIXME use a shared one per height
        use std::dbg;
        let cache = self.cache.clone();
        match Self::overlay_idx(dbg!(past_offset)) {
            HistoricalOffset::FutureBlock => None,
            HistoricalOffset::Latest => Some(HistoricalTreeView {
                historical_overlay_offset: 0,
                latest: &self.latest,
                overlays: (&[], &[]),
                cache,
            }),
            HistoricalOffset::OverlayIdx(idx) => Some(HistoricalTreeView {
                historical_overlay_offset: idx,
                latest: &self.latest,
                overlays: {
                    dbg!(self.overlays.len());
                    let (a, b) = self.overlays.as_slices();
                    dbg!(a.len());
                    dbg!(b.len());
                    if idx < a.len() {
                        (&a[idx..], &b[..])
                    } else if idx < (a.len() + b.len()) {
                        (&[], &b[(idx - a.len())..])
                    } else if self.overlays.len() < idx {
                        // we might not have sufficent index despite the index being small enough
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

    /// Adds an overly to the _front_ (the first one to be applied to latest), but does _not_
    /// modify `self.latest`. Care must be taken to retain a coherent inner state when calling
    /// this!
    fn add_overlay(&mut self, overlay: Overlay) {
        // FIXME move the cache entries as well
        self.overlays.push_front(overlay);
        self.cleanup();
    }

    /// Apply the given mutation set to the interior [`Smt`].
    ///
    /// Creates an `Overlay` to be able to reconstruct the previous state of the `Smt`
    /// on-demand and applies the delta as expected using [`Smt::apply_mutations`].
    pub fn apply_mutations(
        &mut self,
        mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), OverlayError> {
        let overlay = Overlay::walkback(&self.latest, &mutation_set)?;
        self.add_overlay(overlay);
        self.latest
            .apply_mutations(mutation_set)
            .map_err(|_fixme| OverlayError("merkle error FIXME"))?;
        Ok(())
    }
}

/// A historical view of the `Smt`
///
/// Pretend we were still at `block_number` of the `Smt`/`AccountTree` in a limited scope of
/// `MAX_HISTORY` entries. The entries are labelled with relative offsets, commonly a `BlockNumber`.
pub struct HistoricalTreeView<'a> {
    historical_overlay_offset: usize,
    latest: &'a Smt,
    // 0 is top, nth is bottom, so if we query we query from the top
    overlays: (&'a [Overlay], &'a [Overlay]),

    cache: RefCell<InnerNodeHashCache>,
}

impl HistoricalTreeView<'_> {
    /// An overlay for the stacks
    fn overlay_iter<'b>(&'b self) -> impl Iterator<Item = &'b Overlay> {
        self.overlays.0.iter().chain(self.overlays.1.iter())
    }

    /// Root of all overlays combined with latest.
    pub fn root(&self) -> Word {
        self.overlay_iter()
            .next()
            .map(|overlay| overlay.root())
            .unwrap_or_else(|| self.latest.root())
    }

    /// Wrapper.
    pub(crate) fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        <Smt as SparseMerkleTree<SMT_DEPTH>>::key_to_leaf_index(key)
    }

    // Dynamically calculate the inner node cache, used for `SmtProof` deduction, and child hashes
    // required to do so. Call this for every entry in the `MerklePath`.
    fn recalc_inner_digest_with_cache(
        &self,
        index_to_get_value_for: NodeIndex,
        oldest_historic_offset: usize,
    ) -> Word {
        // If we already have the value cached, return it
        if let Some(&cached_value) = self
            .cache
            .borrow_mut()
            .entry(oldest_historic_offset)
            .or_default()
            .get(&index_to_get_value_for)
        {
            println!("EARLY EXIT found cached value for: {}", index_to_get_value_for);

            return cached_value;
        }

        // Walk towards the leaves from the given node index to find what needs to be computed
        let mut cache = self.cache.borrow_mut();
        let digest_cache = cache.entry(oldest_historic_offset).or_default();

        // bfs from the provided index
        let mut compute_backlog = VecDeque::new();
        let mut q = VecDeque::new();

        q.push_back(index_to_get_value_for);

        let mut dedup = HashSet::new();

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
                continue;
            }

            compute_backlog.push_back(current);

            // enqueue both again
            let left = current.left_child();
            let right = current.left_child();

            if !digest_cache.contains_key(&left) {
                if !dedup.contains(&left) {
                    q.push_back(left);
                }
            }
            if !digest_cache.contains_key(&right) {
                if !dedup.contains(&left) {
                    q.push_back(right);
                }
            }
        }
        drop(cache);

        // Now compute from leaves to root
        while let Some(node) = compute_backlog.pop_back() {
            let mut cache = self.cache.borrow_mut();
            let digest_cache = cache.entry(oldest_historic_offset).or_default();
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

                // Recursively ensure children are computed
                let left_hash = if let Some(hash) = digest_cache.get(&left).copied() {
                    println!("Found child (left) in cache at: {}", left);
                    hash
                } else {
                    // FIXME ensure we don't call this accidentally via logic errors
                    println!("Fetching latest (left) at: {}", left);
                    // by definition, we use the `EmptyRoots` optimization if and only if there is
                    // no decendent value present under this node. Otherwise we
                    // have to calculate the node anyways, and hence we do not
                    // need to deal with that optimization in this file's scope.
                    self.latest.get_node_hash(node)
                };

                let right_hash = if let Some(hash) = digest_cache.get(&right).copied() {
                    println!("Found child (right) in cache at: {}", right);
                    hash
                } else {
                    // FIXME ensure we don't call this accidentally via logic errors
                    println!("Fetching latest (right) at: {}", right.depth());
                    self.latest.get_node_hash(node)
                };

                // Merge the hashes to get parent hash
                let digest = InnerNode { left: left_hash, right: right_hash }.hash();
                digest_cache.insert(node, digest);
            }
        }

        let mut cache = self.cache.borrow_mut();
        let digest_cache = cache.entry(oldest_historic_offset).or_default();
        digest_cache
            .get(&index_to_get_value_for)
            .copied()
            .expect("We just computed all nodes up to this point")
    }

    // Helper function to get leaf hash at a specific index
    fn get_leaf_hash_at_index(&self, leaf_index: LeafIndex<SMT_DEPTH>) -> Word {
        // Check overlays first
        for overlay in self.overlay_iter() {
            for leaf in overlay.mutated.values() {
                if leaf.index() == leaf_index {
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

        // proof indices include all siblings, so if we want to proof `x`
        //   root
        //    / \
        //  [f]   g
        //     /  \
        //    t   [q]
        //   / \
        //  x  [y]
        //
        //  proof: [y, q, f] (without root! and without the actual leaf!)
        //
        //
        // now we need a way to derive if we can use the `latest.get_node_hash(index)` or _any_
        // decendent got updated, we are going to call this `is_part_of_poisoned_tree(idx)`

        MerklePath::from_iter(index
            .proof_indices()
            // iterates from leaves towards the root
            .map(|index| {
                println!("GET NODE HASH: {index}");
                let h = self.get_node_hash(index);
                println!("GET NODE HASH == DONE DONE DEAL: {index}");
                h
            }))
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        // we know these contain modifications, 'poisoning' the `latest` stack and rendering inner
        // nodes of `latest` uesless for the sake of hash derivation.
        // We want to skip all non-poisoned ones and do lookups from the last poisoning
        let poison_stack = Vec::from_iter(
            self.overlay_iter().map(|overlay| overlay.is_part_of_poisoned_tree(index)),
        );

        use std::dbg;

        dbg!(&poison_stack);

        if let Some(oldest_historic_offset) = poison_stack.iter().position(|&x| x == true) {
            // let latest_affected_block_num = self.block_number.checked_sub(offset as u32)
            //     .expect("By definition offset is at most 33 and cannot be larger than the number
            // of blocks produced since genesis");

            println!(
                "FOund some offset {oldest_historic_offset} supposedly poisned, so we want to use the cache"
            );
            let _ = self.recalc_inner_digest_with_cache(index, oldest_historic_offset); // FIXME
            let mut cache = self.cache.borrow_mut();
            let cache_inner = cache.entry(oldest_historic_offset).or_default();
            let left = cache_inner
                .get(&index.left_child())
                .copied()
                .unwrap_or_else(|| self.latest.get_node_hash(index.left_child()));
            let right = cache_inner
                .get(&index.right_child())
                .copied()
                .unwrap_or_else(|| self.latest.get_node_hash(index.right_child()));
            InnerNode { left, right }
        } else {
            println!("No poisioning detected, use the latest");
            // nothing touched that index ever
            self.latest.get_inner_node(index)
        }
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns [`Self::root()`]. Other hashes are retrieved by calling
    /// [`Self::get_inner_node()`] on the parent, and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root();
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
            SmtLeaf::Empty(x) => {},
        }
        EMPTY_WORD
    }

    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        for overlay in self.overlay_iter() {
            if let Some(value) = overlay.mutated.get(&key) {
                return value.clone();
            }
        }
        self.latest.get_leaf(key)
    }

    pub fn open(&self, key: &Word) -> SmtProof {
        let leaf = self.get_leaf(key);
        let leaf_idx = leaf.index();

        let path = MerklePath::new(Vec::from_iter(
            leaf_idx.index.proof_indices().map(|idx| self.get_node_hash(idx)),
        ));

        SmtProof::new(SparseMerklePath::try_from(path).unwrap(), leaf).unwrap()
    }
}
