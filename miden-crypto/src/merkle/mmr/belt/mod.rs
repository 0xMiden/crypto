use alloc::{collections::BTreeMap, vec::Vec};

use super::{Forest, MmrError};
use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2};

mod bagging;
mod delta;
mod proof;
mod shape;
use bagging::*;
pub use delta::{MmrBeltDelta, PartialMmrBelt};
pub use proof::BeltProof;
use proof::{BeltProofNode, bagging_path_nodes};
use shape::*;

/// Experimental Merkle Mountain Belt prototype.
#[derive(Debug, Clone, Default)]
pub struct MmrBelt {
    mountains: Vec<Option<BeltMountainSlot>>,
    hashes: BeltHashArray,
    bagging: BeltBaggingState,
    last_bagging_update_hashes: usize,
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
        self.add_with_bagging_mode(leaf, true)
    }

    /// Benchmark-only append that skips live summary maintenance.
    ///
    /// This leaves [`Self::summary`] and [`Self::commitment_root`] stale. Rebuild a diagnostic
    /// summary with [`BeltSummary::from_roots`] after calling this method.
    #[cfg(any(test, feature = "internal"))]
    pub fn add_without_bagging_for_benchmark(&mut self, leaf: Word) -> Result<usize, MmrError> {
        self.add_with_bagging_mode(leaf, false)
    }

    fn add_with_bagging_mode(
        &mut self,
        leaf: Word,
        refresh_bagging: bool,
    ) -> Result<usize, MmrError> {
        if self.num_leaves >= Forest::MAX_LEAVES {
            return Err(MmrError::ForestSizeExceeded {
                requested: self.num_leaves.saturating_add(1),
                max: Forest::MAX_LEAVES,
            });
        }

        let old_num_leaves = self.num_leaves;
        let leaf_position = self.num_leaves;
        let leaf_index = leaf_hash_index(leaf_position);
        self.hashes.set(leaf_index, leaf);

        let new_idx = self.push_mountain(BeltMountain::new(leaf_position, leaf_index, leaf));
        self.num_leaves += 1;
        if let Some(prev_idx) = self.mountain_slot(new_idx).prev {
            self.track_mergeable_pair(prev_idx, new_idx);
        }

        let merged = if let Some(right_idx) = self.rightmost_mergeable {
            Some(self.merge_pair(right_idx))
        } else {
            None
        };
        let num_merges = usize::from(merged.is_some());

        if refresh_bagging {
            let leaf_change = ChangedMountain::new(leaf_position, 0, leaf);
            let mut changed = [leaf_change; 2];
            let mut changed_len = 0;

            if let Some(merged) = merged {
                changed[changed_len] = merged;
                changed_len += 1;
                if !merged.contains_position(leaf_position) {
                    changed[changed_len] = leaf_change;
                    changed_len += 1;
                }
            } else {
                changed[changed_len] = leaf_change;
                changed_len += 1;
            }

            self.refresh_bagging_state(old_num_leaves, &changed[..changed_len]);
        }

        Ok(num_merges)
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

    #[cfg(test)]
    fn live_range_roots_for_testing(&self) -> &[Word] {
        self.bagging.range_roots()
    }

    #[cfg(test)]
    fn live_commitment_root_for_testing(&self) -> Word {
        self.bagging.root()
    }

    #[cfg(test)]
    fn bagging_storage_lengths_for_testing(&self) -> [usize; 4] {
        self.bagging.storage_lengths()
    }

    #[cfg(test)]
    fn last_bagging_update_hashes_for_testing(&self) -> usize {
        self.last_bagging_update_hashes
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn peaks(&self) -> Vec<Word> {
        self.ordered_mountains().iter().map(|mountain| mountain.root).collect()
    }

    pub fn commitment_root(&self) -> Word {
        self.bagging.root()
    }

    pub fn summary(&self) -> BeltSummary {
        BeltSummary::from_roots_and_bagging(self.num_leaves, self.peaks(), &self.bagging)
            .expect("live mountain-order summary must match the current shape")
    }

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

    fn refresh_bagging_state(&mut self, old_num_leaves: usize, changed: &[ChangedMountain]) {
        let hashes = self.bagging.append_update(old_num_leaves, self.num_leaves, changed);
        self.last_bagging_update_hashes = hashes;
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

        let peaks = mountains.iter().map(|mountain| mountain.root).collect::<Vec<_>>();
        nodes.extend(bagging_path_nodes(&peaks, &shape_ranges(&shape), mountain_idx));

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

    fn merge_pair(&mut self, right_idx: usize) -> ChangedMountain {
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
        let root = Poseidon2::merge(&[left.mountain.root, right.mountain.root]);
        let merged = left.mountain.merge(right.mountain, root);
        let changed = ChangedMountain::from_mountain(&merged);
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

        changed
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
    nodes: Vec<Word>,
    present: Vec<u64>,
}

impl BeltHashArray {
    fn get(&self, index: HashIndex) -> Option<Word> {
        self.is_present(index).then(|| self.nodes[index.0])
    }

    fn set(&mut self, index: HashIndex, value: Word) {
        if self.nodes.len() <= index.0 {
            self.nodes.resize(index.0 + 1, EMPTY_WORD);
        }
        let present_word = index.0 / u64::BITS as usize;
        if self.present.len() <= present_word {
            self.present.resize(present_word + 1, 0);
        }

        self.nodes[index.0] = value;
        self.present[present_word] |= 1u64 << (index.0 % u64::BITS as usize);
    }

    fn is_present(&self, index: HashIndex) -> bool {
        let present_word = index.0 / u64::BITS as usize;
        self.present
            .get(present_word)
            .is_some_and(|word| word & (1u64 << (index.0 % u64::BITS as usize)) != 0)
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.nodes.clear();
        self.present.clear();
    }

    #[cfg(test)]
    fn slot_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    fn live_count(&self) -> usize {
        self.present.iter().map(|word| word.count_ones() as usize).sum()
    }

    #[cfg(test)]
    fn value_slot_bytes_for_testing() -> usize {
        core::mem::size_of::<Word>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeltSummary {
    pub(super) num_leaves: usize,
    roots: Vec<Word>,
    commitment_root: Word,
    #[cfg(test)]
    range_roots: Vec<Word>,
}

impl BeltSummary {
    pub fn from_roots(num_leaves: usize, roots: &[Word]) -> Result<Self, MmrError> {
        let bagging = BeltBaggingState::from_roots(num_leaves, roots)?;

        Ok(Self {
            num_leaves,
            roots: roots.to_vec(),
            commitment_root: bagging.root(),
            #[cfg(test)]
            range_roots: bagging.range_roots().to_vec(),
        })
    }

    pub fn from_peaks(num_leaves: usize, peaks: &[Word]) -> Result<Self, MmrError> {
        Self::from_roots(num_leaves, peaks)
    }

    fn from_roots_and_bagging(
        num_leaves: usize,
        roots: Vec<Word>,
        bagging: &BeltBaggingState,
    ) -> Result<Self, MmrError> {
        let expected = shape_len_for_num_leaves(num_leaves);
        if roots.len() != expected {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {expected} peaks for {num_leaves} leaves but got {}",
                roots.len()
            )));
        }

        Ok(Self {
            num_leaves,
            roots,
            commitment_root: bagging.root(),
            #[cfg(test)]
            range_roots: bagging.range_roots().to_vec(),
        })
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn roots(&self) -> &[Word] {
        &self.roots
    }

    pub fn commitment_root(&self) -> Word {
        self.commitment_root
    }

    pub fn root(&self) -> Word {
        self.commitment_root()
    }

    #[cfg(test)]
    fn range_roots_for_testing(&self) -> &[Word] {
        &self.range_roots
    }
}

#[derive(Debug, Clone)]
pub(super) struct BeltMountain {
    pub(super) start: usize,
    pub(super) height: usize,
    index: HashIndex,
    pub(super) root: Word,
}

impl BeltMountain {
    fn new(start: usize, index: HashIndex, root: Word) -> Self {
        Self { start, height: 0, index, root }
    }

    fn merge(self, other: Self, root: Word) -> Self {
        debug_assert_eq!(self.height, other.height);
        debug_assert_eq!(self.start + self.size(), other.start);

        let index = parent_hash_index(self.index);
        debug_assert_eq!(index, parent_hash_index(other.index));
        Self {
            start: self.start,
            height: self.height + 1,
            index,
            root,
        }
    }

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

#[cfg(test)]
mod tests;
