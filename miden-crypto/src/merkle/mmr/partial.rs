use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use winter_utils::{Deserializable, Serializable};

use super::{MmrDelta, MmrProof};
use crate::{
    Word,
    merkle::{
        InnerNodeInfo, MerklePath, Rpo256,
        mmr::{InOrderIndex, MmrError, MmrPeaks, forest::Forest},
    },
};

// TYPE ALIASES
// ================================================================================================

type NodeMap = BTreeMap<InOrderIndex, Word>;

// PARTIAL MERKLE MOUNTAIN RANGE
// ================================================================================================
/// Partially materialized Merkle Mountain Range (MMR), used to efficiently store and update the
/// authentication paths for a subset of the elements in a full MMR.
///
/// This structure store only the authentication path for a value, the value itself is stored
/// separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMmr {
    /// The version of the MMR.
    ///
    /// This value serves the following purposes:
    ///
    /// - The forest is a counter for the total number of elements in the MMR.
    /// - Since the MMR is an append-only structure, every change to it causes a change to the
    ///   `forest`, so this value has a dual purpose as a version tag.
    /// - The bits in the forest also corresponds to the count and size of every perfect binary
    ///   tree that composes the MMR structure, which server to compute indexes and perform
    ///   validation.
    pub(crate) forest: Forest,

    /// The MMR peaks.
    ///
    /// The peaks are used for two reasons:
    ///
    /// 1. It authenticates the addition of an element to the [PartialMmr], ensuring only valid
    ///    elements are tracked.
    /// 2. During a MMR update peaks can be merged by hashing the left and right hand sides. The
    ///    peaks are used as the left hand.
    ///
    /// All the peaks of every tree in the MMR forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    pub(crate) peaks: Vec<Word>,

    /// Authentication nodes used to construct merkle paths for a subset of the MMR's leaves.
    ///
    /// This does not include the MMR's peaks nor the tracked nodes, only the elements required to
    /// construct their authentication paths. This property is used to detect when elements can be
    /// safely removed, because they are no longer required to authenticate any element in the
    /// [PartialMmr].
    ///
    /// The elements in the MMR are referenced using a in-order tree index. This indexing scheme
    /// permits for easy computation of the relative nodes (left/right children, sibling, parent),
    /// which is useful for traversal. The indexing is also stable, meaning that merges to the
    /// trees in the MMR can be represented without rewrites of the indexes.
    pub(crate) nodes: NodeMap,

    /// Flag indicating if the odd element should be tracked.
    ///
    /// This flag is necessary because the sibling of the odd doesn't exist yet, so it can not be
    /// added into `nodes` to signal the value is being tracked.
    pub(crate) track_latest: bool,
}

impl Default for PartialMmr {
    /// Creates a new [PartialMmr] with default values.
    fn default() -> Self {
        let forest = Forest::empty();
        let peaks = Vec::new();
        let nodes = BTreeMap::new();
        let track_latest = false;

        Self { forest, peaks, nodes, track_latest }
    }
}

impl PartialMmr {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [PartialMmr] instantiated from the specified peaks.
    pub fn from_peaks(peaks: MmrPeaks) -> Self {
        let forest = peaks.forest();
        let peaks = peaks.into();
        let nodes = BTreeMap::new();
        let track_latest = false;

        Self { forest, peaks, nodes, track_latest }
    }

    /// Returns a new [PartialMmr] instantiated from the specified components.
    ///
    /// This constructor does not check the consistency between peaks and nodes. If the specified
    /// peaks are nodes are inconsistent, the returned partial MMR may exhibit undefined behavior.
    pub fn from_parts(peaks: MmrPeaks, nodes: NodeMap, track_latest: bool) -> Self {
        let forest = peaks.forest();
        let peaks = peaks.into();

        Self { forest, peaks, nodes, track_latest }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current `forest` of this [PartialMmr].
    ///
    /// This value corresponds to the version of the [PartialMmr] and the number of leaves in the
    /// underlying MMR.
    pub fn forest(&self) -> Forest {
        self.forest
    }

    /// Returns the number of leaves in the underlying MMR for this [PartialMmr].
    pub fn num_leaves(&self) -> usize {
        self.forest.num_leaves()
    }

    /// Returns the peaks of the MMR for this [PartialMmr].
    pub fn peaks(&self) -> MmrPeaks {
        // expect() is OK here because the constructor ensures that MMR peaks can be constructed
        // correctly
        MmrPeaks::new(self.forest, self.peaks.clone()).expect("invalid MMR peaks")
    }

    /// Returns true if this partial MMR tracks an authentication path for the leaf at the
    /// specified position.
    pub fn is_tracked(&self, pos: usize) -> bool {
        let leaves = self.forest.num_leaves();
        if pos >= leaves {
            return false;
        } else if pos == leaves - 1 && self.forest.has_single_leaf_tree() {
            // if the number of leaves in the MMR is odd and the position is for the last leaf
            // whether the leaf is tracked is defined by the `track_latest` flag
            return self.track_latest;
        }

        let leaf_index = InOrderIndex::from_leaf_pos(pos);
        self.is_tracked_node(&leaf_index)
    }

    /// Given a leaf position, returns the Merkle path to its corresponding peak, or None if this
    /// partial MMR does not track an authentication paths for the specified leaf.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if the specified position is greater-or-equal than the number of leaves
    /// in the underlying MMR.
    pub fn open(&self, pos: usize) -> Result<Option<MmrProof>, MmrError> {
        let tree_bit = self
            .forest
            .leaf_to_corresponding_tree(pos)
            .ok_or(MmrError::PositionNotFound(pos))?;
        let depth = tree_bit as usize;

        let mut nodes = Vec::with_capacity(depth);
        let mut idx = InOrderIndex::from_leaf_pos(pos);

        while let Some(node) = self.nodes.get(&idx.sibling()) {
            nodes.push(*node);
            idx = idx.parent();
        }

        // If there are nodes then the path must be complete, otherwise it is a bug
        debug_assert!(nodes.is_empty() || nodes.len() == depth);

        if nodes.len() != depth {
            // The requested `pos` is not being tracked.
            Ok(None)
        } else {
            Ok(Some(MmrProof {
                forest: self.forest,
                position: pos,
                merkle_path: MerklePath::new(nodes),
            }))
        }
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator nodes of all authentication paths of this [PartialMmr].
    pub fn nodes(&self) -> impl Iterator<Item = (&InOrderIndex, &Word)> {
        self.nodes.iter()
    }

    /// Returns an iterator over inner nodes of this [PartialMmr] for the specified leaves.
    ///
    /// The order of iteration is not defined. If a leaf is not presented in this partial MMR it
    /// is silently ignored.
    pub fn inner_nodes<'a, I: Iterator<Item = (usize, Word)> + 'a>(
        &'a self,
        mut leaves: I,
    ) -> impl Iterator<Item = InnerNodeInfo> + 'a {
        let stack = if let Some((pos, leaf)) = leaves.next() {
            let idx = InOrderIndex::from_leaf_pos(pos);
            vec![(idx, leaf)]
        } else {
            Vec::new()
        };

        InnerNodeIterator {
            nodes: &self.nodes,
            leaves,
            stack,
            seen_nodes: BTreeSet::new(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a new peak and optionally track it. Returns a vector of the authentication nodes
    /// inserted into this [PartialMmr] as a result of this operation.
    ///
    /// When `track` is `true` the new leaf is tracked.
    pub fn add(&mut self, leaf: Word, track: bool) -> Vec<(InOrderIndex, Word)> {
        self.forest.append_leaf();
        // We just incremented the forest, so this cannot panic.
        let merges = self.forest.smallest_tree_height_unchecked();
        let mut new_nodes = Vec::with_capacity(merges);

        let peak = if merges == 0 {
            self.track_latest = track;
            leaf
        } else {
            let mut track_right = track;
            let mut track_left = self.track_latest;

            let mut right = leaf;
            let mut right_idx = self.forest.rightmost_in_order_index();

            for _ in 0..merges {
                let left = self.peaks.pop().expect("Missing peak");
                let left_idx = right_idx.sibling();

                if track_right {
                    let old = self.nodes.insert(left_idx, left);
                    new_nodes.push((left_idx, left));

                    debug_assert!(
                        old.is_none(),
                        "Idx {left_idx:?} already contained an element {old:?}",
                    );
                };
                if track_left {
                    let old = self.nodes.insert(right_idx, right);
                    new_nodes.push((right_idx, right));

                    debug_assert!(
                        old.is_none(),
                        "Idx {right_idx:?} already contained an element {old:?}",
                    );
                };

                // Update state for the next iteration.
                // --------------------------------------------------------------------------------

                // This layer is merged, go up one layer.
                right_idx = right_idx.parent();

                // Merge the current layer. The result is either the right element of the next
                // merge, or a new peak.
                right = Rpo256::merge(&[left, right]);

                // This iteration merged the left and right nodes, the new value is always used as
                // the next iteration's right node. Therefore the tracking flags of this iteration
                // have to be merged into the right side only.
                track_right = track_right || track_left;

                // On the next iteration, a peak will be merged. If any of its children are tracked,
                // then we have to track the left side
                track_left = self.is_tracked_node(&right_idx.sibling());
            }
            right
        };

        self.peaks.push(peak);

        new_nodes
    }

    /// Adds the authentication path represented by [MerklePath] if it is valid.
    ///
    /// The `leaf_pos` refers to the global position of the leaf in the MMR, these are 0-indexed
    /// values assigned in a strictly monotonic fashion as elements are inserted into the MMR,
    /// this value corresponds to the values used in the MMR structure.
    ///
    /// The `leaf` corresponds to the value at `leaf_pos`, and `path` is the authentication path for
    /// that element up to its corresponding Mmr peak. The `leaf` is only used to compute the root
    /// from the authentication path to valid the data, only the authentication data is saved in
    /// the structure. If the value is required it should be stored out-of-band.
    pub fn track(
        &mut self,
        leaf_pos: usize,
        leaf: Word,
        path: &MerklePath,
    ) -> Result<(), MmrError> {
        // Checks there is a tree with same depth as the authentication path, if not the path is
        // invalid.
        let tree = Forest::new(1 << path.depth());
        if (tree & self.forest).is_empty() {
            return Err(MmrError::UnknownPeak(path.depth()));
        };

        if leaf_pos + 1 == self.forest.num_leaves()
            && path.depth() == 0
            && self.peaks.last().is_some_and(|v| *v == leaf)
        {
            self.track_latest = true;
            return Ok(());
        }

        // ignore the trees smaller than the target (these elements are position after the current
        // target and don't affect the target leaf_pos)
        let target_forest = self.forest ^ (self.forest & tree.all_smaller_trees_unchecked());
        let peak_pos = target_forest.num_trees() - 1;

        // translate from mmr leaf_pos to merkle path
        let path_idx = leaf_pos - (target_forest ^ tree).num_leaves();

        // Compute the root of the authentication path, and check it matches the current version of
        // the PartialMmr.
        let computed = path
            .compute_root(path_idx as u64, leaf)
            .map_err(MmrError::MerkleRootComputationFailed)?;
        if self.peaks[peak_pos] != computed {
            return Err(MmrError::PeakPathMismatch);
        }

        let mut idx = InOrderIndex::from_leaf_pos(leaf_pos);
        for leaf in path.nodes() {
            self.nodes.insert(idx.sibling(), *leaf);
            idx = idx.parent();
        }

        Ok(())
    }

    /// Removes a leaf of the [PartialMmr] and the unused nodes from the authentication path.
    ///
    /// Note: `leaf_pos` corresponds to the position in the MMR and not on an individual tree.
    pub fn untrack(&mut self, leaf_pos: usize) {
        let mut idx = InOrderIndex::from_leaf_pos(leaf_pos);

        // `idx` represent the element that can be computed by the authentication path, because
        // these elements can be computed they are not saved for the authentication of the current
        // target. In other words, if the idx is present it was added for the authentication of
        // another element, and no more elements should be removed otherwise it would remove that
        // element's authentication data.
        while self.nodes.remove(&idx.sibling()).is_some() && !self.nodes.contains_key(&idx) {
            idx = idx.parent();
        }
    }

    /// Applies updates to this [PartialMmr] and returns a vector of new authentication nodes
    /// inserted into the partial MMR.
    pub fn apply(&mut self, delta: MmrDelta) -> Result<Vec<(InOrderIndex, Word)>, MmrError> {
        if delta.forest < self.forest {
            return Err(MmrError::InvalidPeaks(format!(
                "forest of mmr delta {} is less than current forest {}",
                delta.forest, self.forest
            )));
        }

        let mut inserted_nodes = Vec::new();

        if delta.forest == self.forest {
            if !delta.data.is_empty() {
                return Err(MmrError::InvalidUpdate);
            }

            return Ok(inserted_nodes);
        }

        // find the tree merges
        let changes = self.forest ^ delta.forest;
        // `largest_tree_unchecked()` panics if `changes` is empty. `changes` cannot be empty
        // unless `self.forest == delta.forest`, which is guarded against above.
        let largest = changes.largest_tree_unchecked();
        // The largest tree itself also cannot be an empty forest, so this cannot panic either.
        let merges = self.forest & largest.all_smaller_trees_unchecked();

        debug_assert!(
            !self.track_latest || merges.has_single_leaf_tree(),
            "if there is an odd element, a merge is required"
        );

        // count the number elements needed to produce largest from the current state
        let (merge_count, new_peaks) = if !merges.is_empty() {
            let depth = largest.smallest_tree_height_unchecked();
            // `merges` also cannot be an empty forest, so this cannot panic either.
            let skipped = merges.smallest_tree_height_unchecked();
            let computed = merges.num_trees() - 1;
            let merge_count = depth - skipped - computed;

            let new_peaks = delta.forest & largest.all_smaller_trees_unchecked();

            (merge_count, new_peaks)
        } else {
            (0, changes)
        };

        // verify the delta size
        if delta.data.len() != merge_count + new_peaks.num_trees() {
            return Err(MmrError::InvalidUpdate);
        }

        // keeps track of how many data elements from the update have been consumed
        let mut update_count = 0;

        if !merges.is_empty() {
            // starts at the smallest peak and follows the merged peaks
            let mut peak_idx = self.forest.root_in_order_index();

            // match order of the update data while applying it
            self.peaks.reverse();

            // set to true when the data is needed for authentication paths updates
            let mut track = self.track_latest;
            self.track_latest = false;

            let mut peak_count = 0;
            let mut target = merges.smallest_tree_unchecked();
            let mut new = delta.data[0];
            update_count += 1;

            while target < largest {
                // check if either the left or right subtrees have saved for authentication paths.
                // If so, turn tracking on to update those paths.
                if target != Forest::new(1) && !track {
                    track = self.is_tracked_node(&peak_idx);
                }

                // update data only contains the nodes from the right subtrees, left nodes are
                // either previously known peaks or computed values
                let (left, right) = if !(target & merges).is_empty() {
                    let peak = self.peaks[peak_count];
                    let sibling_idx = peak_idx.sibling();

                    // if the sibling peak is tracked, add this peaks to the set of
                    // authentication nodes
                    if self.is_tracked_node(&sibling_idx) {
                        self.nodes.insert(peak_idx, new);
                        inserted_nodes.push((peak_idx, new));
                    }
                    peak_count += 1;
                    (peak, new)
                } else {
                    let update = delta.data[update_count];
                    update_count += 1;
                    (new, update)
                };

                if track {
                    let sibling_idx = peak_idx.sibling();
                    if peak_idx.is_left_child() {
                        self.nodes.insert(sibling_idx, right);
                        inserted_nodes.push((sibling_idx, right));
                    } else {
                        self.nodes.insert(sibling_idx, left);
                        inserted_nodes.push((sibling_idx, left));
                    }
                }

                peak_idx = peak_idx.parent();
                new = Rpo256::merge(&[left, right]);
                target = target.next_larger_tree();
            }

            debug_assert!(peak_count == merges.num_trees());

            // restore the peaks order
            self.peaks.reverse();
            // remove the merged peaks
            self.peaks.truncate(self.peaks.len() - peak_count);
            // add the newly computed peak, the result of the merges
            self.peaks.push(new);
        }

        // The rest of the update data is composed of peaks. None of these elements can contain
        // tracked elements because the peaks were unknown, and it is not possible to add elements
        // for tacking without authenticating it to a peak.
        self.peaks.extend_from_slice(&delta.data[update_count..]);
        self.forest = delta.forest;

        debug_assert!(self.peaks.len() == self.forest.num_trees());

        Ok(inserted_nodes)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this [PartialMmr] tracks authentication path for the node at the specified
    /// index.
    fn is_tracked_node(&self, node_index: &InOrderIndex) -> bool {
        if node_index.is_leaf() {
            self.nodes.contains_key(&node_index.sibling())
        } else {
            let left_child = node_index.left_child();
            let right_child = node_index.right_child();
            self.nodes.contains_key(&left_child) | self.nodes.contains_key(&right_child)
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MmrPeaks> for PartialMmr {
    fn from(peaks: MmrPeaks) -> Self {
        Self::from_peaks(peaks)
    }
}

impl From<PartialMmr> for MmrPeaks {
    fn from(partial_mmr: PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks).unwrap()
    }
}

impl From<&MmrPeaks> for PartialMmr {
    fn from(peaks: &MmrPeaks) -> Self {
        Self::from_peaks(peaks.clone())
    }
}

impl From<&PartialMmr> for MmrPeaks {
    fn from(partial_mmr: &PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks.clone()).unwrap()
    }
}

// ITERATORS
// ================================================================================================

/// An iterator over every inner node of the [PartialMmr].
pub struct InnerNodeIterator<'a, I: Iterator<Item = (usize, Word)>> {
    nodes: &'a NodeMap,
    leaves: I,
    stack: Vec<(InOrderIndex, Word)>,
    seen_nodes: BTreeSet<InOrderIndex>,
}

impl<I: Iterator<Item = (usize, Word)>> Iterator for InnerNodeIterator<'_, I> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((idx, node)) = self.stack.pop() {
            let parent_idx = idx.parent();
            let new_node = self.seen_nodes.insert(parent_idx);

            // if we haven't seen this node's parent before, and the node has a sibling, return
            // the inner node defined by the parent of this node, and move up the branch
            if new_node && let Some(sibling) = self.nodes.get(&idx.sibling()) {
                let (left, right) = if parent_idx.left_child() == idx {
                    (node, *sibling)
                } else {
                    (*sibling, node)
                };
                let parent = Rpo256::merge(&[left, right]);
                let inner_node = InnerNodeInfo { value: parent, left, right };

                self.stack.push((parent_idx, parent));
                return Some(inner_node);
            }

            // the previous leaf has been processed, try to process the next leaf
            if let Some((pos, leaf)) = self.leaves.next() {
                let idx = InOrderIndex::from_leaf_pos(pos);
                self.stack.push((idx, leaf));
            }
        }

        None
    }
}

impl Serializable for PartialMmr {
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        self.forest.num_leaves().write_into(target);
        self.peaks.write_into(target);
        self.nodes.write_into(target);
        target.write_bool(self.track_latest);
    }
}

impl Deserializable for PartialMmr {
    fn read_from<R: winter_utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, winter_utils::DeserializationError> {
        let forest = Forest::new(usize::read_from(source)?);
        let peaks = Vec::<Word>::read_from(source)?;
        let nodes = NodeMap::read_from(source)?;
        let track_latest = source.read_bool()?;

        Ok(Self { forest, peaks, nodes, track_latest })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeSet, vec::Vec};

    use winter_utils::{Deserializable, Serializable};

    use super::{MmrPeaks, PartialMmr};
    use crate::{
        Word,
        merkle::{
            NodeIndex, int_to_node,
            mmr::{Mmr, forest::Forest},
            store::MerkleStore,
        },
    };

    const LEAVES: [Word; 7] = [
        int_to_node(0),
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
    ];

    #[test]
    fn test_partial_mmr_apply_delta() {
        // build an MMR with 10 nodes (2 peaks) and a partial MMR based on it
        let mut mmr = Mmr::default();
        (0..10).for_each(|i| mmr.add(int_to_node(i)));
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        // add authentication path for position 1 and 8
        {
            let node = mmr.get(1).unwrap();
            let proof = mmr.open(1).unwrap();
            partial_mmr.track(1, node, &proof.merkle_path).unwrap();
        }

        {
            let node = mmr.get(8).unwrap();
            let proof = mmr.open(8).unwrap();
            partial_mmr.track(8, node, &proof.merkle_path).unwrap();
        }

        // add 2 more nodes into the MMR and validate apply_delta()
        (10..12).for_each(|i| mmr.add(int_to_node(i)));
        validate_apply_delta(&mmr, &mut partial_mmr);

        // add 1 more node to the MMR, validate apply_delta() and start tracking the node
        mmr.add(int_to_node(12));
        validate_apply_delta(&mmr, &mut partial_mmr);
        {
            let node = mmr.get(12).unwrap();
            let proof = mmr.open(12).unwrap();
            partial_mmr.track(12, node, &proof.merkle_path).unwrap();
            assert!(partial_mmr.track_latest);
        }

        // by this point we are tracking authentication paths for positions: 1, 8, and 12

        // add 3 more nodes to the MMR (collapses to 1 peak) and validate apply_delta()
        (13..16).for_each(|i| mmr.add(int_to_node(i)));
        validate_apply_delta(&mmr, &mut partial_mmr);
    }

    fn validate_apply_delta(mmr: &Mmr, partial: &mut PartialMmr) {
        let tracked_leaves = partial
            .nodes
            .iter()
            .filter(|&(index, _)| index.is_leaf())
            .map(|(index, _)| index.sibling())
            .collect::<Vec<_>>();
        let nodes_before = partial.nodes.clone();

        // compute and apply delta
        let delta = mmr.get_delta(partial.forest(), mmr.forest()).unwrap();
        let nodes_delta = partial.apply(delta).unwrap();

        // new peaks were computed correctly
        assert_eq!(mmr.peaks(), partial.peaks());

        let mut expected_nodes = nodes_before;
        for (key, value) in nodes_delta {
            // nodes should not be duplicated
            assert!(expected_nodes.insert(key, value).is_none());
        }

        // new nodes should be a combination of original nodes and delta
        assert_eq!(expected_nodes, partial.nodes);

        // make sure tracked leaves open to the same proofs as in the underlying MMR
        for index in tracked_leaves {
            let pos = index.inner() / 2;
            let proof1 = partial.open(pos).unwrap().unwrap();
            let proof2 = mmr.open(pos).unwrap();
            assert_eq!(proof1, proof2);
        }
    }

    #[test]
    fn test_partial_mmr_inner_nodes_iterator() {
        // build the MMR
        let mmr: Mmr = LEAVES.into();
        let first_peak = mmr.peaks().peaks()[0];

        // -- test single tree ----------------------------

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // create partial MMR and add authentication path to node at position 1
        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        partial_mmr.track(1, node1, &proof1.merkle_path).unwrap();

        // empty iterator should have no nodes
        assert_eq!(partial_mmr.inner_nodes([].iter().cloned()).next(), None);

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1)].iter().cloned()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let path1 = store.get_path(first_peak, index1).unwrap().path;

        assert_eq!(path1, proof1.merkle_path);

        // -- test no duplicates --------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        let node0 = mmr.get(0).unwrap();
        let proof0 = mmr.open(0).unwrap();

        let node2 = mmr.get(2).unwrap();
        let proof2 = mmr.open(2).unwrap();

        partial_mmr.track(0, node0, &proof0.merkle_path).unwrap();
        partial_mmr.track(1, node1, &proof1.merkle_path).unwrap();
        partial_mmr.track(2, node2, &proof2.merkle_path).unwrap();

        // make sure there are no duplicates
        let leaves = [(0, node0), (1, node1), (2, node2)];
        let mut nodes = BTreeSet::new();
        for node in partial_mmr.inner_nodes(leaves.iter().cloned()) {
            assert!(nodes.insert(node.value));
        }

        // and also that the store is still be built correctly
        store.extend(partial_mmr.inner_nodes(leaves.iter().cloned()));

        let index0 = NodeIndex::new(2, 0).unwrap();
        let index1 = NodeIndex::new(2, 1).unwrap();
        let index2 = NodeIndex::new(2, 2).unwrap();

        let path0 = store.get_path(first_peak, index0).unwrap().path;
        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path2 = store.get_path(first_peak, index2).unwrap().path;

        assert_eq!(path0, proof0.merkle_path);
        assert_eq!(path1, proof1.merkle_path);
        assert_eq!(path2, proof2.merkle_path);

        // -- test multiple trees -------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        let node5 = mmr.get(5).unwrap();
        let proof5 = mmr.open(5).unwrap();

        partial_mmr.track(1, node1, &proof1.merkle_path).unwrap();
        partial_mmr.track(5, node5, &proof5.merkle_path).unwrap();

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1), (5, node5)].iter().cloned()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let index5 = NodeIndex::new(1, 1).unwrap();

        let second_peak = mmr.peaks().peaks()[1];

        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path5 = store.get_path(second_peak, index5).unwrap().path;

        assert_eq!(path1, proof1.merkle_path);
        assert_eq!(path5, proof5.merkle_path);
    }

    #[test]
    fn test_partial_mmr_add_without_track() {
        let mut mmr = Mmr::default();
        let empty_peaks = MmrPeaks::new(Forest::empty(), vec![]).unwrap();
        let mut partial_mmr = PartialMmr::from_peaks(empty_peaks);

        for el in (0..256).map(int_to_node) {
            mmr.add(el);
            partial_mmr.add(el, false);

            assert_eq!(mmr.peaks(), partial_mmr.peaks());
            assert_eq!(mmr.forest(), partial_mmr.forest());
        }
    }

    #[test]
    fn test_partial_mmr_add_with_track() {
        let mut mmr = Mmr::default();
        let empty_peaks = MmrPeaks::new(Forest::empty(), vec![]).unwrap();
        let mut partial_mmr = PartialMmr::from_peaks(empty_peaks);

        for i in 0..256 {
            let el = int_to_node(i as u64);
            mmr.add(el);
            partial_mmr.add(el, true);

            assert_eq!(mmr.peaks(), partial_mmr.peaks());
            assert_eq!(mmr.forest(), partial_mmr.forest());

            for pos in 0..i {
                let mmr_proof = mmr.open(pos).unwrap();
                let partialmmr_proof = partial_mmr.open(pos).unwrap().unwrap();
                assert_eq!(mmr_proof, partialmmr_proof);
            }
        }
    }

    #[test]
    fn test_partial_mmr_add_existing_track() {
        let mut mmr = Mmr::from((0..7).map(int_to_node));

        // derive a partial Mmr from it which tracks authentication path to leaf 5
        let mut partial_mmr = PartialMmr::from_peaks(mmr.peaks());
        let path_to_5 = mmr.open(5).unwrap().merkle_path;
        let leaf_at_5 = mmr.get(5).unwrap();
        partial_mmr.track(5, leaf_at_5, &path_to_5).unwrap();

        // add a new leaf to both Mmr and partial Mmr
        let leaf_at_7 = int_to_node(7);
        mmr.add(leaf_at_7);
        partial_mmr.add(leaf_at_7, false);

        // the openings should be the same
        assert_eq!(mmr.open(5).unwrap(), partial_mmr.open(5).unwrap().unwrap());
    }

    #[test]
    fn test_partial_mmr_serialization() {
        let mmr = Mmr::from((0..7).map(int_to_node));
        let partial_mmr = PartialMmr::from_peaks(mmr.peaks());

        let bytes = partial_mmr.to_bytes();
        let decoded = PartialMmr::read_from_bytes(&bytes).unwrap();

        assert_eq!(partial_mmr, decoded);
    }

    #[test]
    fn test_partial_mmr_untrack() {
        // build the MMR
        let mmr: Mmr = LEAVES.into();

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // get path and node for position 2
        let node2 = mmr.get(2).unwrap();
        let proof2 = mmr.open(2).unwrap();

        // create partial MMR and add authentication path to nodes at position 1 and 2
        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        partial_mmr.track(1, node1, &proof1.merkle_path).unwrap();
        partial_mmr.track(2, node2, &proof2.merkle_path).unwrap();

        // untrack nodes at positions 1 and 2
        partial_mmr.untrack(1);
        partial_mmr.untrack(2);

        // nodes should not longer be tracked
        assert!(!partial_mmr.is_tracked(1));
        assert!(!partial_mmr.is_tracked(2));
        assert_eq!(partial_mmr.nodes().count(), 0);
    }
}
