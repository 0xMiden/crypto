use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

use super::{Forest, MmrError};
use crate::{EMPTY_WORD, Felt, Word, ZERO, hash::poseidon2::Poseidon2};

/// Domain separator for the final root, which binds the leaf count into the commitment.
///
/// Because the belt shape is a pure function of the leaf count (Lemma 6), binding the count makes
/// the root commit to the entire structure: it cannot be reinterpreted under a different length.
const BELT_ROOT_DOMAIN: Felt = Felt::new_unchecked(0x4d4d_425f_524f_4f54); // "MMB_ROOT"

/// Prototype implementation of the Merkle Mountain Belt construction.
///
/// This type is intentionally reference-oriented: it keeps live mountains in a linked list and
/// re-derives belt ranges, summaries, and proofs from that list while the paper mechanics settle.
/// Appends use stable mountain slots, local links, a mergeable-pair stack, and indexed hash-array
/// storage for committed nodes. Increment proofs are not yet implemented.
#[derive(Debug, Clone, Default)]
pub struct MmrBelt {
    mountains: Vec<Option<BeltMountainSlot>>,
    hashes: BeltHashArray,
    free_mountain_slots: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    mergeable_pairs: Vec<MergeablePair>,
    next_slot_generation: u64,
    num_leaves: usize,
}

impl MmrBelt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, leaf: Word) -> Result<usize, MmrError> {
        if self.num_leaves >= Forest::MAX_LEAVES {
            return Err(MmrError::ForestSizeExceeded {
                requested: self.num_leaves.saturating_add(1),
                max: Forest::MAX_LEAVES,
            });
        }

        let leaf_index = leaf_hash_index(self.num_leaves);
        self.hashes.set(leaf_index, leaf);

        let new_idx = self.push_mountain(BeltMountain::new(self.num_leaves, leaf_index));
        self.num_leaves += 1;
        if let Some(prev_idx) = self.mountain_slot(new_idx).prev {
            self.track_mergeable_pair(prev_idx, new_idx);
        }

        if let Some(right_idx) = self.pop_mergeable_pair() {
            self.merge_pair(right_idx);
            Ok(1)
        } else {
            Ok(0)
        }
    }

    #[cfg(test)]
    fn mountain_heights(&self) -> Vec<usize> {
        self.ordered_mountains().iter().map(|mountain| mountain.height).collect()
    }

    #[cfg(test)]
    fn storage_slots_for_testing(&self) -> usize {
        self.mountains.len()
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Returns the ordered mountain peaks: the additive mountain-order summary.
    ///
    /// These are the mountain roots from left (oldest) to right (newest). Unlike the single
    /// double-bagged [`BeltSummary::root`], this list is incremental: after a `k`-increment only
    /// its `O(log k)` rightmost entries change (see [`MmrBelt::delta`]).
    pub fn peaks(&self) -> Vec<Word> {
        self.ordered_mountains()
            .iter()
            .map(|mountain| self.hash_at(mountain.index))
            .collect()
    }

    pub fn summary(&self) -> BeltSummary {
        BeltSummary {
            num_leaves: self.num_leaves,
            root: bag_peaks(self.num_leaves, &self.peaks()),
        }
    }

    /// Returns the delta needed to update a mountain-order summary from `from_num_leaves` leaves to
    /// the current state.
    ///
    /// By Lemma 9 of the MMB paper, the peak lists of two states differ in only `O(log k)` hashes,
    /// all at the rightmost end, so the delta carries just the changed tail of the peak list. It
    /// also carries the `O(log² k)` within-mountain authentication nodes needed to extend any
    /// tracked leaf whose mountain merged, so a [`PartialMmrBelt`] never has to re-track.
    ///
    /// # Errors
    /// Returns an error if `from_num_leaves` exceeds the current leaf count.
    pub fn delta(&self, from_num_leaves: usize) -> Result<MmrBeltDelta, MmrError> {
        if from_num_leaves > self.num_leaves {
            return Err(MmrError::ForestOutOfBounds(from_num_leaves, self.num_leaves));
        }

        let common = common_peak_prefix_len(from_num_leaves, self.num_leaves);
        let peaks = self.peaks();

        let from_shape = shape_mountains(from_num_leaves);
        let to_shape = shape_mountains(self.num_leaves);
        let mut merge_auth = BTreeMap::new();

        for absorbed in &from_shape[common..] {
            let to_idx = shape_mountain_for_position(&to_shape, absorbed.start)
                .expect("absorbed leaves still exist in the new state");
            let to_height = to_shape[to_idx].height;

            for (_, sibling_start, height) in
                climb_to_peak(absorbed.start, absorbed.height, to_height)
            {
                merge_auth
                    .entry((sibling_start, height))
                    .or_insert_with(|| self.node_at(sibling_start, height));
            }
        }

        Ok(MmrBeltDelta {
            from_num_leaves,
            to_num_leaves: self.num_leaves,
            new_tail_peaks: peaks[common..].to_vec(),
            merge_auth,
        })
    }

    fn node_at(&self, start: usize, height: usize) -> Word {
        self.hash_at(node_hash_index(start, height))
    }

    fn hash_at(&self, index: HashIndex) -> Word {
        self.hashes.get(index).expect("hash must be present in storage")
    }

    pub fn open(&self, position: usize) -> Result<BeltProof, MmrError> {
        if position >= self.num_leaves {
            return Err(MmrError::PositionNotFound(position));
        }

        let mountains = self.ordered_mountains();
        let shape = shape_from_mountains(&mountains);
        let mountain_idx = shape_mountain_for_position(&shape, position)
            .ok_or(MmrError::PositionNotFound(position))?;
        let mountain = shape[mountain_idx];
        let (leaf, mut nodes) = self.open_within_mountain(position, mountain);

        let peaks = mountains
            .iter()
            .map(|mountain| self.hash_at(mountain.index))
            .collect::<Vec<_>>();
        nodes.extend(bagging_path_nodes(&peaks, &shape_ranges(&shape), mountain_idx));

        Ok(BeltProof { position, leaf, nodes })
    }

    fn open_within_mountain(
        &self,
        position: usize,
        mountain: ShapeMountain,
    ) -> (Word, Vec<BeltProofNode>) {
        let leaf = self.node_at(position, 0);
        let mut nodes = Vec::with_capacity(mountain.height);
        let mut node_start = position;

        for height in 0..mountain.height {
            let (sibling_start, parent_start) = sibling_and_parent_start(node_start, height);
            nodes.push(BeltProofNode {
                value: self.node_at(sibling_start, height),
                side: sibling_side((node_start >> height) & 1 == 0),
            });
            node_start = parent_start;
        }

        (leaf, nodes)
    }

    #[cfg(test)]
    fn range_heights(&self) -> Vec<Vec<usize>> {
        let mountains = self.ordered_mountains();
        let shape = shape_from_mountains(&mountains);
        shape_ranges(&shape)
            .into_iter()
            .map(|range| shape[range].iter().map(|mountain| mountain.height).collect())
            .collect()
    }

    fn push_mountain(&mut self, mountain: BeltMountain) -> usize {
        let generation = self.next_slot_generation;
        self.next_slot_generation += 1;
        let slot = BeltMountainSlot {
            mountain,
            prev: self.tail,
            next: None,
            generation,
        };

        let idx = if let Some(idx) = self.free_mountain_slots.pop() {
            self.mountains[idx] = Some(slot);
            idx
        } else {
            let idx = self.mountains.len();
            self.mountains.push(Some(slot));
            idx
        };

        if let Some(tail_idx) = self.tail {
            self.mountain_slot_mut(tail_idx).next = Some(idx);
        } else {
            self.head = Some(idx);
        }
        self.tail = Some(idx);

        idx
    }

    fn merge_pair(&mut self, right_idx: usize) {
        let left_idx = self
            .mountain_slot(right_idx)
            .prev
            .expect("right member of mergeable pair must have left neighbor");
        let right_next = self.mountain_slot(right_idx).next;
        let left_prev = self.mountain_slot(left_idx).prev;
        let left_generation = self.mountain_slot(left_idx).generation;

        let right = self.mountains[right_idx]
            .take()
            .expect("right member of mergeable pair must be active");
        let left = self.mountains[left_idx]
            .take()
            .expect("left member of mergeable pair must be active");
        let root = Poseidon2::merge(&[
            self.hash_at(left.mountain.index),
            self.hash_at(right.mountain.index),
        ]);
        let merged = left.mountain.merge(right.mountain);
        self.hashes.set(merged.index, root);

        self.mountains[left_idx] = Some(BeltMountainSlot {
            mountain: merged,
            prev: left_prev,
            next: right_next,
            generation: left_generation,
        });

        if let Some(next_idx) = right_next {
            self.mountain_slot_mut(next_idx).prev = Some(left_idx);
        } else {
            self.tail = Some(left_idx);
        }
        self.free_mountain_slots.push(right_idx);

        if let Some(prev_idx) = left_prev {
            self.track_mergeable_pair(prev_idx, left_idx);
        }
        if let Some(next_idx) = right_next {
            self.track_mergeable_pair(left_idx, next_idx);
        }
    }

    fn track_mergeable_pair(&mut self, left_idx: usize, right_idx: usize) {
        if self.is_mergeable_pair(left_idx, right_idx) {
            self.mergeable_pairs.push(MergeablePair {
                right_idx,
                right_generation: self.mountain_slot(right_idx).generation,
            });
        }
    }

    fn pop_mergeable_pair(&mut self) -> Option<usize> {
        while let Some(pair) = self.mergeable_pairs.pop() {
            let right_idx = pair.right_idx;
            let Some(right_slot) = self.mountains.get(right_idx).and_then(Option::as_ref) else {
                continue;
            };
            if right_slot.generation != pair.right_generation {
                continue;
            }
            let Some(left_idx) = right_slot.prev else {
                continue;
            };

            if self.is_mergeable_pair(left_idx, right_idx) {
                return Some(right_idx);
            }
        }

        None
    }

    fn is_mergeable_pair(&self, left_idx: usize, right_idx: usize) -> bool {
        let Some(left_slot) = self.mountains.get(left_idx).and_then(Option::as_ref) else {
            return false;
        };
        let Some(right_slot) = self.mountains.get(right_idx).and_then(Option::as_ref) else {
            return false;
        };

        left_slot.next == Some(right_idx)
            && right_slot.prev == Some(left_idx)
            && left_slot.mountain.height == right_slot.mountain.height
    }

    fn ordered_mountains(&self) -> Vec<&BeltMountain> {
        let mut mountains = Vec::new();
        let mut next = self.head;
        while let Some(idx) = next {
            let slot = self.mountain_slot(idx);
            mountains.push(&slot.mountain);
            next = slot.next;
        }
        mountains
    }

    fn mountain_slot(&self, idx: usize) -> &BeltMountainSlot {
        self.mountains[idx].as_ref().expect("mountain slot must be active")
    }

    fn mountain_slot_mut(&mut self, idx: usize) -> &mut BeltMountainSlot {
        self.mountains[idx].as_mut().expect("mountain slot must be active")
    }
}

#[derive(Debug, Clone)]
struct BeltMountainSlot {
    mountain: BeltMountain,
    prev: Option<usize>,
    next: Option<usize>,
    generation: u64,
}

#[derive(Debug, Clone, Copy)]
struct MergeablePair {
    right_idx: usize,
    right_generation: u64,
}

#[derive(Debug, Clone, Default)]
struct BeltHashArray {
    nodes: Vec<Option<Word>>,
}

impl BeltHashArray {
    fn get(&self, index: HashIndex) -> Option<Word> {
        self.nodes.get(index.0).copied().flatten()
    }

    fn set(&mut self, index: HashIndex, value: Word) {
        if self.nodes.len() <= index.0 {
            self.nodes.resize(index.0 + 1, None);
        }
        self.nodes[index.0] = Some(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeltSummary {
    num_leaves: usize,
    root: Word,
}

impl BeltSummary {
    /// Builds a summary by double-bagging a mountain-order peak list.
    ///
    /// This lets a client that maintains only the additive peak list (see [`MmrBelt::peaks`])
    /// derive the same `O(1)` commitment a full node publishes, without storing the belt
    /// itself.
    ///
    /// # Errors
    /// Returns an error if the number of peaks does not match the shape implied by `num_leaves`.
    pub fn from_peaks(num_leaves: usize, peaks: &[Word]) -> Result<Self, MmrError> {
        let expected = shape_mountains(num_leaves).len();
        if peaks.len() != expected {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {expected} peaks for {num_leaves} leaves but got {}",
                peaks.len()
            )));
        }

        Ok(Self {
            num_leaves,
            root: bag_peaks(num_leaves, peaks),
        })
    }

    /// Returns the number of leaves authenticated by this summary.
    ///
    /// The authenticated commitment is the pair `(num_leaves, root)`. The root alone is not a
    /// length-binding commitment, matching the convention used by the frontier benchmarks.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn root(&self) -> Word {
        self.root
    }
}

/// An incremental update to a mountain-order summary, carrying only the peaks that changed during a
/// `k`-increment.
///
/// The unchanged peaks form a prefix of the peak list (the leftmost mountains never participate in
/// a merge during the increment), so only the rightmost `O(log k)` peaks need to be transmitted. A
/// client applies it to its summary with [`MmrBeltDelta::apply`], and to its tracked leaves with
/// [`PartialMmrBelt::apply`], using the carried `merge_auth` nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrBeltDelta {
    from_num_leaves: usize,
    to_num_leaves: usize,
    new_tail_peaks: Vec<Word>,
    /// Within-mountain authentication nodes, keyed by their `(start, height)` coordinate, that let
    /// a client extend the path of any tracked leaf whose mountain merged during the
    /// increment.
    merge_auth: BTreeMap<(usize, usize), Word>,
}

impl MmrBeltDelta {
    pub fn from_num_leaves(&self) -> usize {
        self.from_num_leaves
    }

    pub fn to_num_leaves(&self) -> usize {
        self.to_num_leaves
    }

    pub fn new_tail_peaks(&self) -> &[Word] {
        &self.new_tail_peaks
    }

    pub fn num_merge_auth_nodes(&self) -> usize {
        self.merge_auth.len()
    }

    /// Applies this delta to a client's `old_peaks` (the mountain-order summary at
    /// [`Self::from_num_leaves`]), returning the updated peak list at [`Self::to_num_leaves`].
    ///
    /// The unchanged prefix length is recomputed from the leaf counts alone, so a client does not
    /// trust the producer's split point.
    ///
    /// # Errors
    /// Returns an error if `old_peaks` does not match the shape implied by
    /// [`Self::from_num_leaves`], or if the delta's tail does not complete the target peak
    /// list.
    pub fn apply(&self, old_peaks: &[Word]) -> Result<Vec<Word>, MmrError> {
        let old_len = shape_mountains(self.from_num_leaves).len();
        if old_peaks.len() != old_len {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {old_len} peaks for {} leaves but got {}",
                self.from_num_leaves,
                old_peaks.len()
            )));
        }

        let common = common_peak_prefix_len(self.from_num_leaves, self.to_num_leaves);
        let new_len = shape_mountains(self.to_num_leaves).len();
        if common + self.new_tail_peaks.len() != new_len {
            return Err(MmrError::InvalidUpdate);
        }

        let mut peaks = old_peaks[..common].to_vec();
        peaks.extend_from_slice(&self.new_tail_peaks);

        Ok(peaks)
    }
}

// PARTIAL MERKLE MOUNTAIN BELT
// ================================================================================================

/// A client-side view of a Merkle Mountain Belt.
///
/// It stores the mountain-order summary `(num_leaves, peaks)` — enough to derive the `O(1)`
/// commitment locally and to authenticate newly tracked leaves — plus the within-mountain
/// authentication path of a tracked subset of leaves. The bagging layers (range and belt nodes) are
/// not stored: a client holding all mountain peaks rebuilds them locally on demand (Lemma 15 of the
/// MMB paper), which keeps tracked state small and lets every append re-bag for free.
///
/// A tracked leaf's within-mountain path is invariant as long as its mountain does not merge (the
/// covered leaves are immutable). [`Self::apply`] extends tracked leaves in place when their
/// mountains merge during the increment, using the delta's carried authentication nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMmrBelt {
    num_leaves: usize,
    peaks: Vec<Word>,
    tracked: BTreeMap<usize, TrackedLeaf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedLeaf {
    leaf: Word,
    mountain_start: usize,
    mountain_height: usize,
    within_path: Vec<BeltProofNode>,
}

impl PartialMmrBelt {
    /// Bootstraps a client view from a trusted mountain-order summary.
    ///
    /// # Errors
    /// Returns an error if the number of peaks does not match the shape implied by `num_leaves`.
    pub fn from_peaks(num_leaves: usize, peaks: Vec<Word>) -> Result<Self, MmrError> {
        let expected = shape_mountains(num_leaves).len();
        if peaks.len() != expected {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {expected} peaks for {num_leaves} leaves but got {}",
                peaks.len()
            )));
        }

        Ok(Self {
            num_leaves,
            peaks,
            tracked: BTreeMap::new(),
        })
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn peaks(&self) -> &[Word] {
        &self.peaks
    }

    pub fn summary(&self) -> BeltSummary {
        BeltSummary {
            num_leaves: self.num_leaves,
            root: bag_peaks(self.num_leaves, &self.peaks),
        }
    }

    pub fn is_tracked(&self, pos: usize) -> bool {
        self.tracked.contains_key(&pos)
    }

    pub fn num_tracked(&self) -> usize {
        self.tracked.len()
    }

    pub fn get(&self, pos: usize) -> Option<Word> {
        self.tracked.get(&pos).map(|tracked| tracked.leaf)
    }

    /// Starts tracking the leaf authenticated by `proof` against the current summary.
    ///
    /// # Errors
    /// Returns an error if the proof does not authenticate against the current summary, or if its
    /// position is out of range.
    pub fn track(&mut self, proof: &BeltProof) -> Result<(), MmrError> {
        if !proof.verify(&self.summary()) {
            return Err(MmrError::PeakPathMismatch);
        }

        let shape = shape_mountains(self.num_leaves);
        let mountain_idx = shape_mountain_for_position(&shape, proof.position())
            .ok_or(MmrError::PositionNotFound(proof.position()))?;
        let mountain = shape[mountain_idx];

        self.tracked.insert(
            proof.position(),
            TrackedLeaf {
                leaf: proof.leaf(),
                mountain_start: mountain.start,
                mountain_height: mountain.height,
                within_path: proof.nodes[..mountain.height].to_vec(),
            },
        );

        Ok(())
    }

    pub fn untrack(&mut self, pos: usize) -> bool {
        self.tracked.remove(&pos).is_some()
    }

    /// Rebuilds a membership proof for a tracked leaf, deriving the bagging path from local peaks.
    pub fn open(&self, pos: usize) -> Result<Option<BeltProof>, MmrError> {
        let Some(tracked) = self.tracked.get(&pos) else {
            return Ok(None);
        };

        let shape = shape_mountains(self.num_leaves);
        let mountain_idx =
            shape_mountain_for_position(&shape, pos).ok_or(MmrError::PositionNotFound(pos))?;

        let mut nodes = tracked.within_path.clone();
        nodes.extend(bagging_path_nodes(&self.peaks, &shape_ranges(&shape), mountain_idx));

        Ok(Some(BeltProof { position: pos, leaf: tracked.leaf, nodes }))
    }

    /// Applies an increment delta, advancing the summary and every tracked leaf to the delta's
    /// target state.
    ///
    /// Tracked leaves whose mountain merged during the increment have their within-mountain path
    /// extended in place using the delta's authentication nodes, so no re-tracking is ever needed.
    ///
    /// # Errors
    /// Returns an error if the delta does not originate from the current state, if it does not
    /// apply cleanly to the current peaks, or if it lacks an authentication node required to
    /// extend a tracked leaf.
    pub fn apply(&mut self, delta: &MmrBeltDelta) -> Result<(), MmrError> {
        if delta.from_num_leaves() != self.num_leaves {
            return Err(MmrError::InvalidUpdate);
        }

        self.peaks = delta.apply(&self.peaks)?;
        self.num_leaves = delta.to_num_leaves();

        let new_shape = shape_mountains(self.num_leaves);
        for (&pos, tracked) in self.tracked.iter_mut() {
            let mountain_idx = shape_mountain_for_position(&new_shape, pos)
                .ok_or(MmrError::PositionNotFound(pos))?;
            let new_mountain = new_shape[mountain_idx];

            for (node_start, sibling_start, height) in
                climb_to_peak(tracked.mountain_start, tracked.mountain_height, new_mountain.height)
            {
                let &value = delta
                    .merge_auth
                    .get(&(sibling_start, height))
                    .ok_or(MmrError::InvalidUpdate)?;
                tracked.within_path.push(BeltProofNode {
                    value,
                    side: sibling_side((node_start >> height) & 1 == 0),
                });
            }

            tracked.mountain_start = new_mountain.start;
            tracked.mountain_height = new_mountain.height;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeltProof {
    position: usize,
    leaf: Word,
    nodes: Vec<BeltProofNode>,
}

impl BeltProof {
    pub fn position(&self) -> usize {
        self.position
    }

    pub fn leaf(&self) -> Word {
        self.leaf
    }

    pub fn verify(&self, summary: &BeltSummary) -> bool {
        if self.position >= summary.num_leaves {
            return false;
        }

        let Some(expected_sides) = proof_sides_for_position(summary.num_leaves, self.position)
        else {
            return false;
        };

        if self.nodes.len() != expected_sides.len()
            || self
                .nodes
                .iter()
                .zip(expected_sides)
                .any(|(node, expected_side)| node.side != expected_side)
        {
            return false;
        }

        let bagged = self.nodes.iter().fold(self.leaf, |current, node| match node.side {
            SiblingSide::Left => Poseidon2::merge(&[node.value, current]),
            SiblingSide::Right => Poseidon2::merge(&[current, node.value]),
        });

        bind_length(bagged, summary.num_leaves) == summary.root
    }

    #[cfg(test)]
    fn set_leaf_for_testing(&mut self, leaf: Word) {
        self.leaf = leaf;
    }

    #[cfg(test)]
    fn set_position_for_testing(&mut self, position: usize) {
        self.position = position;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BeltProofNode {
    value: Word,
    side: SiblingSide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiblingSide {
    Left,
    Right,
}

#[derive(Debug, Clone)]
struct BeltMountain {
    start: usize,
    height: usize,
    index: HashIndex,
}

impl BeltMountain {
    fn new(start: usize, index: HashIndex) -> Self {
        Self { start, height: 0, index }
    }

    fn merge(self, other: Self) -> Self {
        debug_assert_eq!(self.height, other.height);
        debug_assert_eq!(self.start + self.size(), other.start);

        let index = parent_hash_index(self.index);
        debug_assert_eq!(index, parent_hash_index(other.index));
        Self {
            start: self.start,
            height: self.height + 1,
            index,
        }
    }

    fn size(&self) -> usize {
        1usize << self.height
    }
}

fn forward_bag<T>(nodes: T) -> Word
where
    T: IntoIterator<Item = Word>,
{
    let mut iter = nodes.into_iter();
    let Some(first) = iter.next() else {
        return EMPTY_WORD;
    };

    iter.fold(first, |left, right| Poseidon2::merge(&[left, right]))
}

// The target's subtree is the left child at every level it climbs, so its path is the prefix bag
// to its left (one node, if any) followed by each peak to its right.
fn forward_tree_path(nodes: &[Word], target_idx: usize) -> Vec<BeltProofNode> {
    debug_assert!(!nodes.is_empty());
    debug_assert!(target_idx < nodes.len());

    let mut path = Vec::with_capacity(nodes.len() - target_idx);
    if target_idx > 0 {
        let left = forward_bag(nodes[..target_idx].iter().copied());
        path.push(BeltProofNode { value: left, side: SiblingSide::Left });
    }
    for &node in &nodes[target_idx + 1..] {
        path.push(BeltProofNode { value: node, side: SiblingSide::Right });
    }
    path
}

fn bagging_path_nodes(
    peaks: &[Word],
    ranges: &[Range<usize>],
    mountain_idx: usize,
) -> Vec<BeltProofNode> {
    let range_idx = ranges
        .iter()
        .position(|range| range.contains(&mountain_idx))
        .expect("mountain must be part of a range");
    let range = ranges[range_idx].clone();

    let mut nodes = forward_tree_path(&peaks[range.clone()], mountain_idx - range.start);
    let range_roots = ranges
        .iter()
        .map(|range| forward_bag(peaks[range.clone()].iter().copied()))
        .collect::<Vec<_>>();
    nodes.extend(forward_tree_path(&range_roots, range_idx));
    nodes
}

fn proof_sides_for_position(num_leaves: usize, position: usize) -> Option<Vec<SiblingSide>> {
    if position >= num_leaves {
        return None;
    }

    let mountains = shape_mountains(num_leaves);
    let mountain_idx = shape_mountain_for_position(&mountains, position)?;
    let mountain = mountains[mountain_idx];
    let local_position = position - mountain.start;

    let mut sides = balanced_tree_sides(mountain.height, local_position);

    let ranges = shape_ranges(&mountains);
    let range_idx = ranges.iter().position(|range| range.contains(&mountain_idx))?;
    let range = ranges[range_idx].clone();
    sides.extend(forward_tree_sides(range.len(), mountain_idx - range.start));
    sides.extend(forward_tree_sides(ranges.len(), range_idx));

    Some(sides)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HashIndex(usize);

fn leaf_hash_index(position: usize) -> HashIndex {
    HashIndex(2 * (position + 1) + 1)
}

fn parent_hash_index(child: HashIndex) -> HashIndex {
    let span = 1usize << (child.0.trailing_zeros() as usize + 2);
    HashIndex(child.0 + child.0 % span)
}

#[cfg(test)]
fn hash_children(parent: HashIndex) -> (HashIndex, HashIndex) {
    debug_assert!(parent.0 % 2 == 0);
    let span = 1usize << (parent.0.trailing_zeros() as usize - 1);
    (HashIndex(parent.0 - 3 * span), HashIndex(parent.0 - span))
}

fn node_hash_index(start: usize, height: usize) -> HashIndex {
    let mut index = leaf_hash_index(start);
    for _ in 0..height {
        index = parent_hash_index(index);
    }
    index
}

/// This is the common currency for all belt geometry: both the prover (over its live mountain
/// list) and the verifier (over a shape derived solely from the leaf count) reduce to a slice of
/// `ShapeMountain` before computing ranges, positions, and proof handedness.
#[derive(Debug, Clone, Copy)]
struct ShapeMountain {
    start: usize,
    height: usize,
}

impl ShapeMountain {
    fn size(&self) -> usize {
        1usize << self.height
    }
}

fn shape_from_mountains(mountains: &[&BeltMountain]) -> Vec<ShapeMountain> {
    mountains
        .iter()
        .map(|mountain| ShapeMountain {
            start: mountain.start,
            height: mountain.height,
        })
        .collect()
}

/// Derives the left-to-right mountain shape directly from the leaf count, in O(log n) time.
///
/// By Lemma 6 of the MMB paper, if `num_leaves + 1 = (b_t .. b_1 b_0)` in binary then there are
/// `t = floor(log2(num_leaves + 1))` mountains, and the mountain at position `i` (counted from the
/// right, starting at zero) has height `s_i = i + b_i`; the leading bit `b_t` is ignored. This lets
/// a verifier reconstruct the geometry without replaying every append.
fn shape_mountains(num_leaves: usize) -> Vec<ShapeMountain> {
    if num_leaves == 0 {
        return Vec::new();
    }

    let bits = num_leaves + 1;
    let num_mountains = bits.ilog2() as usize;

    let mut mountains = Vec::with_capacity(num_mountains);
    let mut start = 0;
    for position in (0..num_mountains).rev() {
        let bit = (bits >> position) & 1;
        let height = position + bit;
        mountains.push(ShapeMountain { start, height });
        start += 1usize << height;
    }
    debug_assert_eq!(start, num_leaves);

    mountains
}

fn shape_mountain_for_position(mountains: &[ShapeMountain], position: usize) -> Option<usize> {
    mountains
        .iter()
        .position(|mountain| position < mountain.start + mountain.size())
}

fn shape_ranges(mountains: &[ShapeMountain]) -> Vec<Range<usize>> {
    if mountains.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut start = 0;
    for idx in 0..mountains.len() - 1 {
        if shape_range_split_after(mountains, idx) {
            ranges.push(start..idx + 1);
            start = idx + 1;
        }
    }
    ranges.push(start..mountains.len());
    ranges
}

fn shape_range_split_after(mountains: &[ShapeMountain], idx: usize) -> bool {
    let left = mountains[idx].height;
    let right = mountains[idx + 1].height;
    let drops_by_two = left == right + 2;
    let left_is_right_member_of_mergeable_pair = idx > 0 && mountains[idx - 1].height == left;

    drops_by_two || left_is_right_member_of_mergeable_pair
}

// `start` is a multiple of `2^height`, so the parity of `start >> height` decides handedness: even
// is a left child (sibling to the right), odd is a right child (sibling to the left).
fn sibling_and_parent_start(start: usize, height: usize) -> (usize, usize) {
    let span = 1usize << height;
    if (start >> height) & 1 == 0 {
        (start + span, start)
    } else {
        (start - span, start - span)
    }
}

// The delta producer and client walk this same sequence to avoid path-extension drift.
fn climb_to_peak(
    start: usize,
    from_height: usize,
    to_height: usize,
) -> impl Iterator<Item = (usize, usize, usize)> {
    let mut start = start;
    (from_height..to_height).map(move |height| {
        let node_start = start;
        let (sibling_start, parent_start) = sibling_and_parent_start(start, height);
        start = parent_start;
        (node_start, sibling_start, height)
    })
}

fn bag_peaks(num_leaves: usize, peaks: &[Word]) -> Word {
    let shape = shape_mountains(num_leaves);
    debug_assert_eq!(shape.len(), peaks.len());

    let range_roots = shape_ranges(&shape)
        .into_iter()
        .map(|range| forward_bag(peaks[range].iter().copied()))
        .collect::<Vec<_>>();

    bind_length(forward_bag(range_roots), num_leaves)
}

/// Binds the leaf count into a bagged root, yielding the final length-committing commitment.
///
/// This is the step that closes the `hash_peaks()` shape-omission gap (issue #863): the returned
/// root authenticates `num_leaves`, and hence the belt's entire shape, on its own.
fn bind_length(bagged_root: Word, num_leaves: usize) -> Word {
    let length = Word::new([Felt::new_unchecked(num_leaves as u64), ZERO, ZERO, ZERO]);
    Poseidon2::merge_in_domain(&[bagged_root, length], BELT_ROOT_DOMAIN)
}

/// Returns the number of leftmost peaks shared between the `from` and `to` states.
///
/// Two mountains with the same start offset and height cover the same immutable leaf range, so they
/// have identical peak hashes. The shared prefix is therefore the longest run of position-identical
/// mountains, and everything past it is what a [`MmrBeltDelta`] must carry.
fn common_peak_prefix_len(from_num_leaves: usize, to_num_leaves: usize) -> usize {
    let from_shape = shape_mountains(from_num_leaves);
    let to_shape = shape_mountains(to_num_leaves);

    from_shape
        .iter()
        .zip(to_shape.iter())
        .take_while(|(from, to)| from.start == to.start && from.height == to.height)
        .count()
}

fn sibling_side(is_left_child: bool) -> SiblingSide {
    if is_left_child {
        SiblingSide::Right
    } else {
        SiblingSide::Left
    }
}

fn balanced_tree_sides(height: usize, mut local_position: usize) -> Vec<SiblingSide> {
    let mut sides = Vec::with_capacity(height);
    for _ in 0..height {
        sides.push(sibling_side(local_position & 1 == 0));
        local_position >>= 1;
    }
    sides
}

fn forward_tree_sides(len: usize, target_idx: usize) -> Vec<SiblingSide> {
    debug_assert!(len > 0);
    debug_assert!(target_idx < len);

    let mut sides = Vec::with_capacity(len - target_idx);
    if target_idx > 0 {
        sides.push(SiblingSide::Left);
    }
    sides.resize(sides.len() + (len - 1 - target_idx), SiblingSide::Right);
    sides
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{
        BeltSummary, HashIndex, MmrBelt, PartialMmrBelt, hash_children, leaf_hash_index,
        node_hash_index, parent_hash_index, shape_mountains, shape_ranges,
    };
    use crate::{Word, hash::poseidon2::Poseidon2, merkle::int_to_node};

    fn shape_heights(num_leaves: usize) -> Vec<usize> {
        shape_mountains(num_leaves).iter().map(|mountain| mountain.height).collect()
    }

    fn shape_hash_indices(num_leaves: usize) -> Vec<usize> {
        shape_mountains(num_leaves)
            .iter()
            .map(|mountain| node_hash_index(mountain.start, mountain.height).0)
            .collect()
    }

    fn hash_range(leaves: &[Word], start: usize, height: usize) -> Word {
        if height == 0 {
            return leaves[start];
        }

        let half = 1usize << (height - 1);
        Poseidon2::merge(&[
            hash_range(leaves, start, height - 1),
            hash_range(leaves, start + half, height - 1),
        ])
    }

    #[test]
    fn belt_hash_indices_match_clojure_layout() {
        let leaf_indices = (0..6).map(|position| leaf_hash_index(position).0).collect::<Vec<_>>();
        assert_eq!(leaf_indices, vec![3, 5, 7, 9, 11, 13]);

        assert_eq!(parent_hash_index(HashIndex(3)), HashIndex(6));
        assert_eq!(parent_hash_index(HashIndex(5)), HashIndex(6));
        assert_eq!(hash_children(HashIndex(6)), (HashIndex(3), HashIndex(5)));

        assert_eq!(parent_hash_index(HashIndex(6)), HashIndex(12));
        assert_eq!(parent_hash_index(HashIndex(10)), HashIndex(12));
        assert_eq!(hash_children(HashIndex(12)), (HashIndex(6), HashIndex(10)));
    }

    #[test]
    fn belt_shape_hash_indices_match_peak_layout() {
        assert_eq!(shape_hash_indices(1), vec![3]);
        assert_eq!(shape_hash_indices(2), vec![6]);
        assert_eq!(shape_hash_indices(3), vec![6, 7]);
        assert_eq!(shape_hash_indices(4), vec![6, 10]);
        assert_eq!(shape_hash_indices(5), vec![12, 11]);
        assert_eq!(shape_hash_indices(9), vec![12, 20, 19]);
        assert_eq!(shape_hash_indices(10), vec![12, 20, 22]);
    }

    #[test]
    fn belt_hash_array_stores_live_mountain_nodes() {
        let mut belt = MmrBelt::new();
        let leaves = (0..64).map(int_to_node).collect::<Vec<_>>();

        for leaf in leaves.iter().copied() {
            belt.add(leaf).unwrap();
        }

        for mountain in belt.ordered_mountains() {
            for height in 0..=mountain.height {
                let width = 1usize << height;
                for start in (mountain.start..mountain.start + mountain.size()).step_by(width) {
                    assert_eq!(
                        belt.hashes.get(node_hash_index(start, height)),
                        Some(hash_range(&leaves, start, height)),
                        "missing hash for node [{start}, {})",
                        start + width
                    );
                }
            }
        }
    }

    #[test]
    fn belt_lazy_append_height_sequence() {
        let mut belt = MmrBelt::new();
        let expected = [
            vec![0],
            vec![1],
            vec![1, 0],
            vec![1, 1],
            vec![2, 0],
            vec![2, 1],
            vec![2, 1, 0],
            vec![2, 1, 1],
            vec![2, 2, 0],
            vec![2, 2, 1],
            vec![3, 1, 0],
            vec![3, 1, 1],
            vec![3, 2, 0],
        ];

        for (idx, expected_heights) in expected.into_iter().enumerate() {
            belt.add(int_to_node(idx as u64)).unwrap();
            assert_eq!(belt.mountain_heights(), expected_heights);
        }
    }

    #[test]
    fn belt_append_performs_at_most_one_mountain_merge() {
        let mut belt = MmrBelt::new();

        for idx in 0..128 {
            let merge_count = belt.add(int_to_node(idx)).unwrap();
            assert!(merge_count <= 1);
        }
    }

    #[test]
    fn belt_append_touches_constant_local_storage() {
        let mut belt = MmrBelt::new();

        for idx in 0..128 {
            let before = belt.storage_slots_for_testing();
            belt.add(int_to_node(idx)).unwrap();
            let after = belt.storage_slots_for_testing();

            assert!(after - before <= 2);
        }
    }

    #[test]
    fn belt_range_splits_follow_mmb_rules() {
        let mut belt = MmrBelt::new();
        let expected = [
            vec![vec![0]],
            vec![vec![1]],
            vec![vec![1, 0]],
            vec![vec![1, 1]],
            vec![vec![2], vec![0]],
            vec![vec![2, 1]],
            vec![vec![2, 1, 0]],
            vec![vec![2, 1, 1]],
            vec![vec![2, 2], vec![0]],
            vec![vec![2, 2], vec![1]],
            vec![vec![3], vec![1, 0]],
            vec![vec![3], vec![1, 1]],
            vec![vec![3, 2], vec![0]],
            vec![vec![3, 2, 1]],
            vec![vec![3, 2, 1, 0]],
            vec![vec![3, 2, 1, 1]],
        ];

        for (idx, expected_ranges) in expected.into_iter().enumerate() {
            belt.add(int_to_node(idx as u64)).unwrap();
            assert_eq!(belt.range_heights(), expected_ranges);
        }
    }

    #[test]
    fn belt_summary_root_is_stable_for_same_leaves() {
        let mut first = MmrBelt::new();
        let mut second = MmrBelt::new();

        for idx in 0..32 {
            let leaf = int_to_node(idx);
            first.add(leaf).unwrap();
            second.add(leaf).unwrap();
        }

        assert_eq!(first.summary().root(), second.summary().root());
        assert_eq!(first.summary().num_leaves(), 32);
    }

    #[test]
    fn belt_openings_verify_for_all_leaves() {
        let mut belt = MmrBelt::new();
        let leaves = (0..37).map(int_to_node).collect::<Vec<_>>();
        for leaf in leaves.iter().copied() {
            belt.add(leaf).unwrap();
        }
        let summary = belt.summary();

        for (position, leaf) in leaves.into_iter().enumerate() {
            let proof = belt.open(position).unwrap();
            assert_eq!(proof.position(), position);
            assert_eq!(proof.leaf(), leaf);
            assert!(proof.verify(&summary));
        }
    }

    #[test]
    fn belt_opening_rejects_wrong_leaf() {
        let mut belt = MmrBelt::new();
        for idx in 0..16 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let summary = belt.summary();
        let mut proof = belt.open(7).unwrap();

        proof.set_leaf_for_testing(int_to_node(999));

        assert!(!proof.verify(&summary));
    }

    #[test]
    fn belt_opening_rejects_wrong_position() {
        let mut belt = MmrBelt::new();
        for idx in 0..37 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let summary = belt.summary();
        let mut proof = belt.open(7).unwrap();

        proof.set_position_for_testing(5);

        assert!(!proof.verify(&summary));
    }

    #[test]
    fn belt_root_binds_leaf_count() {
        use super::{bind_length, forward_bag};

        let num_leaves = 20usize;
        let mut belt = MmrBelt::new();
        for idx in 0..num_leaves {
            belt.add(int_to_node(idx as u64)).unwrap();
        }
        let summary = belt.summary();

        // Reconstruct the un-bound double-bagging (the raw peak commitment).
        let peaks = belt.peaks();
        let shape = shape_mountains(num_leaves);
        let range_roots = shape_ranges(&shape)
            .into_iter()
            .map(|range| forward_bag(peaks[range].iter().copied()))
            .collect::<Vec<_>>();
        let unbound = forward_bag(range_roots);

        // The published root binds the leaf count: it differs from the raw bagging, and equals the
        // raw bagging only once the count is mixed in. So the count cannot be omitted from the root.
        assert_ne!(unbound, summary.root());
        assert_eq!(bind_length(unbound, num_leaves), summary.root());
        assert_ne!(bind_length(unbound, num_leaves), bind_length(unbound, num_leaves + 1));
    }

    #[test]
    fn belt_shape_derivation_matches_live_structure_across_pow2() {
        let mut belt = MmrBelt::new();
        let leaves = (0..4100u64).map(int_to_node).collect::<Vec<_>>();
        for leaf in leaves.iter().copied() {
            belt.add(leaf).unwrap();
        }
        let summary = belt.summary();

        for (position, leaf) in leaves.into_iter().enumerate() {
            let proof = belt.open(position).unwrap();
            assert_eq!(proof.leaf(), leaf, "leaf mismatch at {position}");
            assert!(proof.verify(&summary), "verify failed at position {position}");
        }
    }

    #[test]
    fn belt_summary_from_peaks_matches_full_summary() {
        let mut belt = MmrBelt::new();
        for idx in 0..100 {
            belt.add(int_to_node(idx)).unwrap();
            let summary = belt.summary();
            let from_peaks = BeltSummary::from_peaks(summary.num_leaves(), &belt.peaks()).unwrap();
            assert_eq!(from_peaks, summary);
        }
    }

    #[test]
    fn belt_delta_resyncs_client_summary() {
        let total = 600usize;
        for from in [0usize, 1, 7, 64, 255, 256, 511] {
            let mut belt = MmrBelt::new();
            for idx in 0..from {
                belt.add(int_to_node(idx as u64)).unwrap();
            }
            let client_peaks = belt.peaks();

            for idx in from..total {
                belt.add(int_to_node(idx as u64)).unwrap();
            }

            let delta = belt.delta(from).unwrap();
            assert_eq!(delta.from_num_leaves(), from);
            assert_eq!(delta.to_num_leaves(), total);

            let updated = delta.apply(&client_peaks).unwrap();
            assert_eq!(updated, belt.peaks(), "resynced peaks must match (from {from})");
            assert_eq!(
                BeltSummary::from_peaks(total, &updated).unwrap(),
                belt.summary(),
                "resynced commitment must match (from {from})"
            );
        }
    }

    #[test]
    fn belt_delta_is_logarithmic_in_increment() {
        let mut belt = MmrBelt::new();
        for idx in 0..100_000u64 {
            belt.add(int_to_node(idx)).unwrap();
        }

        for k in [1usize, 2, 10, 100, 1000] {
            let delta = belt.delta(100_000 - k).unwrap();
            let bound = 2 * (usize::BITS - k.leading_zeros()) as usize + 4;
            assert!(
                delta.new_tail_peaks().len() <= bound,
                "k={k}: tail {} exceeded bound {bound}",
                delta.new_tail_peaks().len()
            );
        }
    }

    #[test]
    fn belt_delta_rejects_future_origin() {
        let mut belt = MmrBelt::new();
        for idx in 0..10 {
            belt.add(int_to_node(idx)).unwrap();
        }
        assert!(belt.delta(11).is_err());
    }

    #[test]
    fn partial_belt_tracks_and_opens_like_full_belt() {
        let mut belt = MmrBelt::new();
        let leaves = (0..50u64).map(int_to_node).collect::<Vec<_>>();
        for leaf in leaves.iter().copied() {
            belt.add(leaf).unwrap();
        }

        let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
        assert_eq!(partial.summary(), belt.summary());

        for position in 0..leaves.len() {
            partial.track(&belt.open(position).unwrap()).unwrap();
        }
        assert_eq!(partial.num_tracked(), leaves.len());

        for (position, leaf) in leaves.iter().copied().enumerate() {
            let proof = partial.open(position).unwrap().unwrap();
            assert_eq!(proof, belt.open(position).unwrap());
            assert_eq!(partial.get(position), Some(leaf));
            assert!(proof.verify(&partial.summary()));
        }
    }

    #[test]
    fn partial_belt_from_peaks_rejects_wrong_count() {
        let mut belt = MmrBelt::new();
        for idx in 0..7 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let mut peaks = belt.peaks();
        peaks.pop();
        assert!(PartialMmrBelt::from_peaks(belt.num_leaves(), peaks).is_err());
    }

    #[test]
    fn partial_belt_track_rejects_unauthenticated_proof() {
        let mut belt = MmrBelt::new();
        for idx in 0..16 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();

        let mut proof = belt.open(5).unwrap();
        proof.set_leaf_for_testing(int_to_node(999));
        assert!(partial.track(&proof).is_err());
        assert!(!partial.is_tracked(5));
    }

    #[test]
    fn partial_belt_apply_extends_all_tracks_in_place() {
        let from = 200usize;
        let to = 260usize;

        let mut belt = MmrBelt::new();
        for idx in 0..from {
            belt.add(int_to_node(idx as u64)).unwrap();
        }

        let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
        for position in 0..from {
            partial.track(&belt.open(position).unwrap()).unwrap();
        }

        for idx in from..to {
            belt.add(int_to_node(idx as u64)).unwrap();
        }

        partial.apply(&belt.delta(from).unwrap()).unwrap();

        assert_eq!(partial.num_leaves(), to);
        assert_eq!(partial.summary(), belt.summary());
        assert_eq!(partial.num_tracked(), from);

        for position in 0..from {
            assert!(partial.is_tracked(position), "leaf {position} must still be tracked");
            assert_eq!(partial.open(position).unwrap().unwrap(), belt.open(position).unwrap());
        }
    }

    #[test]
    fn partial_belt_apply_extends_across_many_increments() {
        let mut belt = MmrBelt::new();
        for idx in 0..40u64 {
            belt.add(int_to_node(idx)).unwrap();
        }

        let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
        let tracked = [0usize, 1, 17, 38, 39];
        for &position in &tracked {
            partial.track(&belt.open(position).unwrap()).unwrap();
        }

        let mut next = 40u64;
        for _ in 0..30 {
            let from = belt.num_leaves();
            for _ in 0..7 {
                belt.add(int_to_node(next)).unwrap();
                next += 1;
            }
            partial.apply(&belt.delta(from).unwrap()).unwrap();

            assert_eq!(partial.summary(), belt.summary());
            for &position in &tracked {
                assert_eq!(partial.open(position).unwrap().unwrap(), belt.open(position).unwrap());
            }
        }
    }

    #[test]
    fn partial_belt_delta_merge_auth_is_polylogarithmic() {
        let mut belt = MmrBelt::new();
        for idx in 0..100_000u64 {
            belt.add(int_to_node(idx)).unwrap();
        }

        for k in [1usize, 2, 16, 256, 4096] {
            let delta = belt.delta(100_000 - k).unwrap();
            let log_k = (usize::BITS - k.leading_zeros()) as usize;
            let bound = 4 * log_k * log_k + 8;
            assert!(
                delta.num_merge_auth_nodes() <= bound,
                "k={k}: {} auth nodes exceeded bound {bound}",
                delta.num_merge_auth_nodes()
            );
        }
    }

    #[test]
    fn partial_belt_open_untracked_returns_none() {
        let mut belt = MmrBelt::new();
        for idx in 0..16 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
        assert!(partial.open(3).unwrap().is_none());
    }

    #[test]
    fn belt_height_sequences_match_paper() {
        // Golden mountain-height sequences S_n published in the MMB paper (arXiv:2511.13582):
        // §3.1 for n = 9, Figure 5 for n = 10, Figures 5/6 for n = 11, and Figure 7/9 for n = 1337.
        // Both the live structure and the O(log n) shape derivation must reproduce them.
        let golden: [(usize, &[usize]); 4] = [
            (9, &[2, 2, 0]),
            (10, &[2, 2, 1]),
            (11, &[3, 1, 0]),
            (1337, &[9, 9, 7, 6, 6, 5, 4, 2, 2, 0]),
        ];

        for (num_leaves, expected) in golden {
            assert_eq!(shape_heights(num_leaves), expected, "shape S_{num_leaves}");

            let mut belt = MmrBelt::new();
            for idx in 0..num_leaves {
                belt.add(int_to_node(idx as u64)).unwrap();
            }
            assert_eq!(belt.mountain_heights(), expected, "live S_{num_leaves}");
        }
    }

    #[test]
    fn belt_merge_peak_lands_in_last_two_ranges() {
        // Lemma 16: when an append performs a merge, the new merge peak sits at the right end of
        // its range, in either the rightmost or second-rightmost range. A merge happens on
        // the append that brings the count to `n` exactly when `n + 1` is not a power of
        // two (Lemma 6.3), and the merge peak then sits at position `nu2(n + 1)` counted
        // from the right (Lemma 6.3).
        for num_leaves in 2..4096usize {
            if (num_leaves + 1).is_power_of_two() {
                continue; // merge step skipped on this append
            }

            let shape = shape_mountains(num_leaves);
            let merge_idx = shape.len() - 1 - (num_leaves + 1).trailing_zeros() as usize;

            let ranges = shape_ranges(&shape);
            let range_idx = ranges
                .iter()
                .position(|range| range.contains(&merge_idx))
                .expect("merge peak must lie in a range");

            assert_eq!(
                ranges[range_idx].end,
                merge_idx + 1,
                "n={num_leaves}: merge peak must sit at the right end of its range"
            );
            assert!(
                range_idx + 2 >= ranges.len(),
                "n={num_leaves}: merge peak must be in the rightmost or second-rightmost range"
            );
        }
    }
}
