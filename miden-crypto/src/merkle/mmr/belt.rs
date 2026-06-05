use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

use super::{Forest, MmrError};
use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FoldDomain {
    Mountain,
    Range,
    Belt,
}

impl FoldDomain {
    fn merge(self, left: Word, right: Word) -> Word {
        match self {
            FoldDomain::Mountain => Poseidon2::merge(&[left, right]),
            FoldDomain::Range => Poseidon2::merge(&[left, right]),
            FoldDomain::Belt => Poseidon2::merge(&[left, right]),
        }
    }
}

/// Prototype implementation of the Merkle Mountain Belt construction.
///
/// This reference-oriented implementation uses stable mountain slots, a mergeable-pair stack, and
/// indexed hash-array storage. Increment proofs are not yet implemented.
#[derive(Debug, Clone, Default)]
pub struct MmrBelt {
    mountains: Vec<Option<BeltMountainSlot>>,
    hashes: BeltHashArray,
    free_mountain_slots: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    rightmost_mergeable: Option<usize>,
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

        if let Some(right_idx) = self.rightmost_mergeable {
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

    #[cfg(test)]
    fn rightmost_mergeable_pair_for_testing(&self) -> Option<(usize, usize)> {
        let right_idx = self.rightmost_mergeable?;
        let right = self.mountain_slot(right_idx);
        let left_idx = right.prev?;
        Some((self.mountain_slot(left_idx).mountain.start, right.mountain.start))
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Returns the left-to-right mountain roots.
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

    /// Returns the delta needed to update a mountain-order summary from `from_num_leaves`.
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
        nodes.extend(bagging_path_nodes(&shape, &peaks, &shape_ranges(&shape), mountain_idx));

        Ok(BeltProof { position, leaf, nodes })
    }

    fn open_within_mountain(
        &self,
        position: usize,
        mountain: ShapeMountain,
    ) -> (Word, Vec<BeltProofNode>) {
        let leaf = self.node_at(position, 0);
        let nodes = climb_to_peak(position, 0, mountain.height)
            .map(|(side, sibling_start, height)| BeltProofNode {
                value: self.node_at(sibling_start, height),
                side,
            })
            .collect();

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
        let slot = BeltMountainSlot {
            mountain,
            prev: self.tail,
            next: None,
            mergeable_prev: None,
            mergeable_next: None,
            in_mergeable_list: false,
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
        let insert_after = if self.mountain_slot(left_idx).in_mergeable_list {
            self.mountain_slot(left_idx).mergeable_prev
        } else {
            self.mountain_slot(right_idx).mergeable_prev
        };

        self.untrack_mergeable_pair(right_idx);
        self.untrack_mergeable_pair(left_idx);

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
            mergeable_prev: None,
            mergeable_next: None,
            in_mergeable_list: false,
        });

        if let Some(next_idx) = right_next {
            self.mountain_slot_mut(next_idx).prev = Some(left_idx);
        } else {
            self.tail = Some(left_idx);
        }
        self.free_mountain_slots.push(right_idx);

        if let Some(prev_idx) = left_prev {
            self.track_mergeable_pair_after(insert_after, prev_idx, left_idx);
        }
        if let Some(next_idx) = right_next {
            self.track_mergeable_pair_after(self.rightmost_mergeable, left_idx, next_idx);
        }
    }

    fn track_mergeable_pair(&mut self, left_idx: usize, right_idx: usize) {
        self.track_mergeable_pair_after(self.rightmost_mergeable, left_idx, right_idx);
    }

    fn track_mergeable_pair_after(
        &mut self,
        prev_pair: Option<usize>,
        left_idx: usize,
        right_idx: usize,
    ) {
        if !self.is_mergeable_pair(left_idx, right_idx)
            || self.mountain_slot(right_idx).in_mergeable_list
        {
            return;
        }

        if let Some(prev_idx) = prev_pair {
            self.mountain_slot_mut(prev_idx).mergeable_next = Some(right_idx);
        }

        let slot = self.mountain_slot_mut(right_idx);
        slot.mergeable_prev = prev_pair;
        slot.mergeable_next = None;
        slot.in_mergeable_list = true;
        self.rightmost_mergeable = Some(right_idx);
    }

    fn untrack_mergeable_pair(&mut self, right_idx: usize) {
        let Some(slot) = self.mountains.get(right_idx).and_then(Option::as_ref) else {
            return;
        };
        if !slot.in_mergeable_list {
            return;
        }

        let prev = slot.mergeable_prev;
        let next = slot.mergeable_next;

        if let Some(prev_idx) = prev {
            self.mountain_slot_mut(prev_idx).mergeable_next = next;
        }
        if let Some(next_idx) = next {
            self.mountain_slot_mut(next_idx).mergeable_prev = prev;
        } else {
            self.rightmost_mergeable = prev;
        }

        let slot = self.mountain_slot_mut(right_idx);
        slot.mergeable_prev = None;
        slot.mergeable_next = None;
        slot.in_mergeable_list = false;
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
    mergeable_prev: Option<usize>,
    mergeable_next: Option<usize>,
    in_mergeable_list: bool,
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
    /// The count lets consumers derive the expected shape and proof handedness.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn root(&self) -> Word {
        self.root
    }
}

/// Incremental update to a mountain-order summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrBeltDelta {
    from_num_leaves: usize,
    to_num_leaves: usize,
    new_tail_peaks: Vec<Word>,
    /// Authentication nodes for extending tracked leaves whose mountain merged.
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

    /// Applies this delta to a client's old mountain-order peak list.
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

/// Client-side view of a Merkle Mountain Belt.
///
/// Stores the mountain-order summary plus within-mountain paths for tracked leaves. Range and belt
/// paths are rebuilt from the local peak list on demand.
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
        nodes.extend(bagging_path_nodes(&shape, &self.peaks, &shape_ranges(&shape), mountain_idx));

        Ok(Some(BeltProof { position: pos, leaf: tracked.leaf, nodes }))
    }

    /// Applies an increment delta to the summary and tracked paths.
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

            for (side, sibling_start, height) in
                climb_to_peak(tracked.mountain_start, tracked.mountain_height, new_mountain.height)
            {
                let &value = delta
                    .merge_auth
                    .get(&(sibling_start, height))
                    .ok_or(MmrError::InvalidUpdate)?;
                tracked.within_path.push(BeltProofNode { value, side });
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

        let Some(steps) = proof_steps_for_position(summary.num_leaves, self.position) else {
            return false;
        };

        if self.nodes.len() != steps.len()
            || self.nodes.iter().zip(&steps).any(|(node, (side, _))| node.side != *side)
        {
            return false;
        }

        let root =
            self.nodes
                .iter()
                .zip(&steps)
                .fold(self.leaf, |current, (node, (side, domain))| match side {
                    SiblingSide::Left => domain.merge(node.value, current),
                    SiblingSide::Right => domain.merge(current, node.value),
                });

        root == summary.root
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

fn bagging_path_nodes(
    shape: &[ShapeMountain],
    peaks: &[Word],
    ranges: &[Range<usize>],
    mountain_idx: usize,
) -> Vec<BeltProofNode> {
    let range_idx = ranges
        .iter()
        .position(|range| range.contains(&mountain_idx))
        .expect("mountain must be part of a range");
    let range = ranges[range_idx].clone();

    let mut nodes = Vec::new();

    let prefix = bag_range(&shape[range.start..mountain_idx], &peaks[range.start..mountain_idx]);
    nodes.push(BeltProofNode { value: prefix, side: SiblingSide::Left });
    for &peak in &peaks[mountain_idx + 1..range.end] {
        nodes.push(BeltProofNode { value: peak, side: SiblingSide::Right });
    }

    let range_roots = ranges
        .iter()
        .map(|range| bag_range(&shape[range.clone()], &peaks[range.clone()]))
        .collect::<Vec<_>>();
    let prefix_belt = bag_belt(&range_roots[..range_idx]);
    nodes.push(BeltProofNode {
        value: prefix_belt,
        side: SiblingSide::Left,
    });
    for &root in &range_roots[range_idx + 1..] {
        nodes.push(BeltProofNode { value: root, side: SiblingSide::Right });
    }

    nodes
}

fn proof_steps_for_position(
    num_leaves: usize,
    position: usize,
) -> Option<Vec<(SiblingSide, FoldDomain)>> {
    if position >= num_leaves {
        return None;
    }

    let shape = shape_mountains(num_leaves);
    let mountain_idx = shape_mountain_for_position(&shape, position)?;
    let mountain = shape[mountain_idx];

    let mut steps: Vec<(SiblingSide, FoldDomain)> =
        balanced_tree_sides(mountain.height, position - mountain.start)
            .into_iter()
            .map(|side| (side, FoldDomain::Mountain))
            .collect();

    let ranges = shape_ranges(&shape);
    let range_idx = ranges.iter().position(|range| range.contains(&mountain_idx))?;
    let range = ranges[range_idx].clone();

    steps.push((SiblingSide::Left, FoldDomain::Range));
    for _ in &shape[mountain_idx + 1..range.end] {
        steps.push((SiblingSide::Right, FoldDomain::Range));
    }

    steps.push((SiblingSide::Left, FoldDomain::Belt));
    for _ in (range_idx + 1)..ranges.len() {
        steps.push((SiblingSide::Right, FoldDomain::Belt));
    }

    Some(steps)
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
    // Lemma 24 closed form for the node covering `[start, start + 2^height)`.
    HashIndex((2 * (start >> height) + 3) << height)
}

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

fn sibling_and_parent_start(start: usize, height: usize) -> (SiblingSide, usize, usize) {
    let span = 1usize << height;
    if (start >> height) & 1 == 0 {
        (SiblingSide::Right, start + span, start)
    } else {
        (SiblingSide::Left, start - span, start - span)
    }
}

fn climb_to_peak(
    start: usize,
    from_height: usize,
    to_height: usize,
) -> impl Iterator<Item = (SiblingSide, usize, usize)> {
    let mut start = start;
    (from_height..to_height).map(move |height| {
        let (side, sibling_start, parent_start) = sibling_and_parent_start(start, height);
        start = parent_start;
        (side, sibling_start, height)
    })
}

fn bag_peaks(num_leaves: usize, peaks: &[Word]) -> Word {
    let shape = shape_mountains(num_leaves);
    debug_assert_eq!(shape.len(), peaks.len());

    let range_roots = shape_ranges(&shape)
        .into_iter()
        .map(|range| bag_range(&shape[range.clone()], &peaks[range]))
        .collect::<Vec<_>>();

    bag_belt(&range_roots)
}

fn bag_range(mountains: &[ShapeMountain], peaks: &[Word]) -> Word {
    debug_assert_eq!(mountains.len(), peaks.len());
    mountains
        .iter()
        .zip(peaks)
        .fold(EMPTY_WORD, |acc, (_, &peak)| FoldDomain::Range.merge(acc, peak))
}

fn bag_belt(range_roots: &[Word]) -> Word {
    range_roots
        .iter()
        .fold(EMPTY_WORD, |acc, &root| FoldDomain::Belt.merge(acc, root))
}

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

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{
        BeltSummary, HashIndex, MmrBelt, PartialMmrBelt, bag_range, hash_children, leaf_hash_index,
        node_hash_index, parent_hash_index, shape_mountains, shape_ranges,
    };
    use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2, merkle::int_to_node};

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
    fn belt_tracks_rightmost_mergeable_pair_without_stale_stack() {
        let mut belt = MmrBelt::new();

        for idx in 0..512 {
            belt.add(int_to_node(idx)).unwrap();

            let mountains = belt.ordered_mountains();
            let expected = mountains
                .windows(2)
                .rev()
                .find(|pair| pair[0].height == pair[1].height)
                .map(|pair| (pair[0].start, pair[1].start));

            assert_eq!(belt.rightmost_mergeable_pair_for_testing(), expected, "after {idx}");
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
    fn belt_root_binds_shape_without_belt_domain_separation() {
        let mut belt = MmrBelt::new();
        for idx in 0..2 {
            belt.add(int_to_node(idx)).unwrap();
        }
        let summary = belt.summary();
        let peaks = belt.peaks();
        assert_eq!(peaks.len(), 1);
        assert_ne!(summary.root(), peaks[0], "root must not be transparent to its peak");

        let mut bigger = MmrBelt::new();
        for idx in 0..3 {
            bigger.add(int_to_node(idx)).unwrap();
        }
        assert_ne!(bigger.summary().root(), summary.root());
    }

    #[test]
    fn belt_second_bagging_uses_plain_merkle_merge() {
        let mut belt = MmrBelt::new();
        for idx in 0..5 {
            belt.add(int_to_node(idx)).unwrap();
        }

        let shape = shape_mountains(belt.num_leaves());
        let peaks = belt.peaks();
        let range_roots = shape_ranges(&shape)
            .into_iter()
            .map(|range| bag_range(&shape[range.clone()], &peaks[range]))
            .collect::<Vec<_>>();
        assert!(range_roots.len() > 1);

        let expected =
            range_roots.iter().fold(EMPTY_WORD, |acc, &root| Poseidon2::merge(&[acc, root]));

        assert_eq!(belt.summary().root(), expected);
    }

    #[test]
    fn belt_range_bagging_uses_plain_merkle_merge() {
        let mut belt = MmrBelt::new();
        for idx in 0..9 {
            belt.add(int_to_node(idx)).unwrap();
        }

        let shape = shape_mountains(belt.num_leaves());
        let peaks = belt.peaks();
        let first_range = shape_ranges(&shape).into_iter().next().unwrap();
        assert!(first_range.len() > 1);

        let expected = peaks[first_range.clone()]
            .iter()
            .fold(EMPTY_WORD, |acc, &peak| Poseidon2::merge(&[acc, peak]));

        assert_eq!(bag_range(&shape[first_range.clone()], &peaks[first_range]), expected);
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
    fn partial_belt_protocol_model_resyncs_after_offline_increment() {
        let from = 128usize;
        let to = 191usize;
        let leaves = (0..to as u64).map(int_to_node).collect::<Vec<_>>();

        let mut full_node = MmrBelt::new();
        for &leaf in &leaves[..from] {
            full_node.add(leaf).unwrap();
        }

        let mut client =
            PartialMmrBelt::from_peaks(full_node.num_leaves(), full_node.peaks()).unwrap();
        for &position in &[0usize, 1, 7, 63, 64, 100, 127] {
            client.track(&full_node.open(position).unwrap()).unwrap();
        }
        assert_eq!(client.summary(), full_node.summary());

        for &leaf in &leaves[from..to] {
            full_node.add(leaf).unwrap();
        }
        let server_delta = full_node.delta(from).unwrap();

        assert_ne!(client.summary(), full_node.summary());
        client.apply(&server_delta).unwrap();
        assert_eq!(client.summary(), full_node.summary());

        for &position in &[0usize, 1, 7, 63, 64, 100, 127] {
            let client_proof = client.open(position).unwrap().unwrap();
            assert!(client_proof.verify(&client.summary()));
            assert_eq!(client_proof, full_node.open(position).unwrap());
            assert_eq!(client.get(position), Some(leaves[position]));
        }

        let newest_position = to - 1;
        client.track(&full_node.open(newest_position).unwrap()).unwrap();
        assert_eq!(client.get(newest_position), Some(leaves[newest_position]));
        assert!(client.open(newest_position).unwrap().unwrap().verify(&client.summary()));
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
        // Golden S_n sequences from arXiv:2511.13582, §3.1 and Figures 5/7/9.
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
        // Lemma 16.
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
