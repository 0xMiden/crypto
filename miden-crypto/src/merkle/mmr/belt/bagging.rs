use alloc::{format, vec::Vec};
use core::ops::Range;

use super::shape::*;
use super::{BeltMountain, MmrError};
use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2};

struct AppendChangedRanges {
    ranges: [Range<usize>; 2],
    len: usize,
}

impl AppendChangedRanges {
    fn new() -> Self {
        Self { ranges: [0..0, 0..0], len: 0 }
    }

    fn push(&mut self, range: Range<usize>) -> Result<(), MmrError> {
        if self.len == self.ranges.len() {
            return Err(MmrError::InvalidUpdate);
        }

        self.ranges[self.len] = range;
        self.len += 1;

        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.ranges[..self.len].iter().cloned()
    }
}

#[derive(Debug, Clone)]
pub(super) struct BeltBaggingState {
    num_leaves: usize,
    range_len: usize,
    pub(super) ranges: Vec<Range<usize>>,
    range_roots: Vec<Word>,
    range_nodes: Vec<Vec<RangeNode>>,
    belt_nodes: Vec<BeltNode>,
}

impl BeltBaggingState {
    pub(super) fn from_roots(num_leaves: usize, roots: &[Word]) -> Result<Self, MmrError> {
        Self::from_roots_with_stats(num_leaves, roots).map(|(state, _)| state)
    }

    pub(super) fn from_roots_with_stats(
        num_leaves: usize,
        roots: &[Word],
    ) -> Result<(Self, usize), MmrError> {
        let shape = shape_mountains(num_leaves);
        if roots.len() != shape.len() {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {} peaks for {num_leaves} leaves but got {}",
                shape.len(),
                roots.len()
            )));
        }

        let mut hashes = 0;
        let ranges = shape_ranges(&shape);
        let mut range_roots = Vec::new();
        let mut range_nodes = Vec::new();
        for range in ranges.iter().cloned() {
            let mut nodes = Vec::with_capacity(range.len());
            let mut prefix = EMPTY_WORD;
            for &root in &roots[range] {
                let node = RangeNode::new(prefix, root);
                hashes += 1;
                prefix = node.root;
                nodes.push(node);
            }
            range_roots.push(prefix);
            range_nodes.push(nodes);
        }

        let range_len = range_roots.len();
        let mut belt_nodes = Vec::with_capacity(range_len);
        let mut prefix = EMPTY_WORD;
        for &range_root in &range_roots {
            let node = BeltNode::new(prefix, range_root);
            hashes += 1;
            prefix = node.root;
            belt_nodes.push(node);
        }

        Ok((
            Self {
                num_leaves,
                range_len,
                ranges,
                range_roots,
                range_nodes,
                belt_nodes,
            },
            hashes,
        ))
    }

    pub(super) fn append_update(
        &mut self,
        old_num_leaves: usize,
        new_num_leaves: usize,
        changed: &[ChangedMountain],
    ) -> usize {
        debug_assert_eq!(old_num_leaves + 1, new_num_leaves);
        debug_assert!(!changed.is_empty());

        if old_num_leaves == 0 {
            debug_assert_eq!(changed.len(), 1);
            debug_assert_eq!(changed[0].mountain, (ShapeMountain { start: 0, height: 0 }));

            let range_node = RangeNode::new(EMPTY_WORD, changed[0].root);
            let belt_node = BeltNode::new(EMPTY_WORD, range_node.root);
            *self = Self {
                num_leaves: new_num_leaves,
                range_len: 1,
                ranges: Vec::from([0..1]),
                range_roots: Vec::from([range_node.root]),
                range_nodes: Vec::from([Vec::from([range_node])]),
                belt_nodes: Vec::from([belt_node]),
            };
            return 2;
        }

        debug_assert_eq!(self.num_leaves, old_num_leaves);
        debug_assert!(self.range_len <= self.ranges.len());
        debug_assert!(self.range_len <= self.range_roots.len());
        debug_assert!(self.range_len <= self.range_nodes.len());
        debug_assert!(self.range_len <= self.belt_nodes.len());

        let recompute_idx = append_shape_recompute_index_trusted(old_num_leaves, changed);
        let common = shape_range_index_for_num_leaves(old_num_leaves, recompute_idx)
            .expect("append recompute index must have an old range");
        let suffix_start = self.ranges[common].start;

        self.num_leaves = new_num_leaves;

        let old_ranges_len = self.range_len;

        let mut hashes = 0;
        let mut range_idx = common;
        let changed_ranges = append_changed_ranges_trusted(new_num_leaves, suffix_start, changed);
        for range in changed_ranges.iter() {
            let changed_root = changed_root_for_range_trusted(new_num_leaves, &range, changed);
            let range_hashes = self.update_changed_range_trusted(
                old_num_leaves,
                new_num_leaves,
                range_idx,
                range.clone(),
                changed_root,
                range_idx,
                old_ranges_len,
            );
            hashes += range_hashes;
            range_idx += 1;
        }

        let new_range_len = range_idx;
        for range_idx in common..new_range_len {
            let range_root = self.range_roots[range_idx];
            let left = if range_idx == 0 {
                EMPTY_WORD
            } else {
                self.belt_nodes[range_idx - 1].root
            };
            let node = BeltNode::new(left, range_root);
            hashes += 1;
            if range_idx == self.belt_nodes.len() {
                self.belt_nodes.push(node);
            } else {
                self.belt_nodes[range_idx] = node;
            }
        }
        self.range_len = new_range_len;

        hashes
    }

    pub(super) fn update_changed_range_trusted(
        &mut self,
        old_num_leaves: usize,
        new_num_leaves: usize,
        range_idx: usize,
        new_range: Range<usize>,
        changed_root: Word,
        first_old_range_idx: usize,
        old_ranges_len: usize,
    ) -> usize {
        debug_assert!(new_range.start < new_range.end);
        debug_assert!(range_idx <= self.ranges.len());
        debug_assert!(range_idx <= self.range_roots.len());
        debug_assert!(range_idx <= self.range_nodes.len());

        let changed_idx = new_range.end - 1;
        let changed = changed_idx - new_range.start;
        let source_range_idx = if changed == 0 {
            None
        } else {
            let old_idx = shape_mountain_index_for_num_leaves(
                old_num_leaves,
                shape_mountain_at_index(new_num_leaves, new_range.start)
                    .expect("new range prefix must start with a mountain"),
            )
            .expect("new range prefix must reuse an old mountain");
            let old_range_idx = shape_range_index_for_num_leaves(old_num_leaves, old_idx)
                .expect("reused mountain must belong to an old range");
            debug_assert!((first_old_range_idx..old_ranges_len).contains(&old_range_idx));
            let old_range = self.ranges[old_range_idx].clone();
            debug_assert_eq!(old_idx, old_range.start);
            debug_assert!(old_range.start + changed <= old_range.end);
            debug_assert!(self.range_nodes[old_range_idx].len() >= changed);
            Some(old_range_idx)
        };

        if range_idx == self.range_nodes.len() {
            self.range_nodes.push(Vec::new());
        }
        if let Some(source_range_idx) = source_range_idx
            && source_range_idx != range_idx
        {
            self.range_nodes.swap(source_range_idx, range_idx);
        }

        let nodes = &mut self.range_nodes[range_idx];
        if changed == 0 {
            nodes.clear();
        } else {
            nodes.truncate(changed);
        }

        let left = nodes.last().map_or(EMPTY_WORD, |node| node.root);
        let node = RangeNode::new(left, changed_root);
        let root = node.root;
        nodes.push(node);

        if range_idx == self.ranges.len() {
            self.ranges.push(new_range);
        } else {
            self.ranges[range_idx] = new_range;
        }
        if range_idx == self.range_roots.len() {
            self.range_roots.push(root);
        } else {
            self.range_roots[range_idx] = root;
        }

        1
    }

    #[cfg(test)]
    pub(super) fn changed_range_nodes(
        &mut self,
        old_num_leaves: usize,
        new_num_leaves: usize,
        new_range: Range<usize>,
        changed_roots: &[ChangedMountain],
        first_old_range_idx: usize,
        old_ranges_len: usize,
    ) -> Result<(Vec<RangeNode>, Word, usize), MmrError> {
        if new_range.start >= new_range.end {
            return Err(MmrError::InvalidUpdate);
        }

        let changed_idx = new_range.end - 1;
        let changed_mountain =
            shape_mountain_at_index(new_num_leaves, changed_idx).ok_or(MmrError::InvalidUpdate)?;
        let changed_root = changed_roots
            .iter()
            .find(|changed| changed.mountain == changed_mountain)
            .map(|changed| changed.root)
            .ok_or(MmrError::InvalidUpdate)?;

        for changed in changed_roots {
            if changed.mountain == changed_mountain {
                continue;
            }
            if let Some(idx) = shape_mountain_index_for_num_leaves(new_num_leaves, changed.mountain)
                && new_range.contains(&idx)
            {
                return Err(MmrError::InvalidUpdate);
            }
        }

        Ok(self.changed_range_nodes_trusted(
            old_num_leaves,
            new_num_leaves,
            new_range,
            changed_root,
            first_old_range_idx,
            old_ranges_len,
        ))
    }

    #[cfg(test)]
    pub(super) fn changed_range_nodes_trusted(
        &mut self,
        old_num_leaves: usize,
        new_num_leaves: usize,
        new_range: Range<usize>,
        changed_root: Word,
        first_old_range_idx: usize,
        old_ranges_len: usize,
    ) -> (Vec<RangeNode>, Word, usize) {
        debug_assert!(new_range.start < new_range.end);

        let changed_idx = new_range.end - 1;
        let changed = changed_idx - new_range.start;
        let mut nodes = if changed == 0 {
            Vec::new()
        } else {
            let old_idx = shape_mountain_index_for_num_leaves(
                old_num_leaves,
                shape_mountain_at_index(new_num_leaves, new_range.start)
                    .expect("new range prefix must start with a mountain"),
            )
            .expect("new range prefix must reuse an old mountain");
            let old_range_idx = shape_range_index_for_num_leaves(old_num_leaves, old_idx)
                .expect("reused mountain must belong to an old range");
            debug_assert!((first_old_range_idx..old_ranges_len).contains(&old_range_idx));
            let old_range = self.ranges[old_range_idx].clone();
            let old_range_nodes = &mut self.range_nodes[old_range_idx];
            debug_assert_eq!(old_idx, old_range.start);
            debug_assert!(old_range.start + changed <= old_range.end);
            debug_assert!(old_range_nodes.len() >= changed);

            old_range_nodes.truncate(changed);
            core::mem::take(old_range_nodes)
        };

        let left = nodes.last().map_or(EMPTY_WORD, |node| node.root);
        let node = RangeNode::new(left, changed_root);
        let root = node.root;
        nodes.push(node);

        (nodes, root, 1)
    }

    #[cfg(test)]
    pub(super) fn range_roots(&self) -> &[Word] {
        &self.range_roots[..self.range_len]
    }

    #[cfg(test)]
    pub(super) fn range_nodes(&self) -> &[Vec<RangeNode>] {
        &self.range_nodes[..self.range_len]
    }

    #[cfg(test)]
    pub(super) fn belt_nodes(&self) -> &[BeltNode] {
        &self.belt_nodes[..self.range_len]
    }

    #[cfg(test)]
    pub(super) fn storage_lengths(&self) -> [usize; 4] {
        [
            self.ranges.len(),
            self.range_roots.len(),
            self.range_nodes.len(),
            self.belt_nodes.len(),
        ]
    }

    pub(super) fn root(&self) -> Word {
        if self.range_len == 0 {
            EMPTY_WORD
        } else {
            self.belt_nodes[self.range_len - 1].root
        }
    }
}

impl PartialEq for BeltBaggingState {
    fn eq(&self, other: &Self) -> bool {
        self.num_leaves == other.num_leaves
            && self.range_len == other.range_len
            && self.ranges.get(..self.range_len) == other.ranges.get(..other.range_len)
            && self.range_roots.get(..self.range_len) == other.range_roots.get(..other.range_len)
            && self.range_nodes.get(..self.range_len) == other.range_nodes.get(..other.range_len)
            && self.belt_nodes.get(..self.range_len) == other.belt_nodes.get(..other.range_len)
    }
}

impl Eq for BeltBaggingState {}

impl Default for BeltBaggingState {
    fn default() -> Self {
        Self {
            num_leaves: 0,
            range_len: 0,
            ranges: Vec::new(),
            range_roots: Vec::new(),
            range_nodes: Vec::new(),
            belt_nodes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RangeNode {
    pub(super) left: Word,
    pub(super) right: Word,
    pub(super) root: Word,
}

impl RangeNode {
    fn new(left: Word, right: Word) -> Self {
        Self {
            left,
            right,
            root: Poseidon2::merge(&[left, right]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BeltNode {
    pub(super) left: Word,
    pub(super) right: Word,
    pub(super) root: Word,
}

impl BeltNode {
    fn new(left: Word, right: Word) -> Self {
        Self {
            left,
            right,
            root: Poseidon2::merge(&[left, right]),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ChangedMountain {
    pub(super) mountain: ShapeMountain,
    pub(super) root: Word,
}

impl ChangedMountain {
    pub(super) fn new(start: usize, height: usize, root: Word) -> Self {
        Self {
            mountain: ShapeMountain { start, height },
            root,
        }
    }

    pub(super) fn from_mountain(mountain: &BeltMountain) -> Self {
        Self::new(mountain.start, mountain.height, mountain.root)
    }

    pub(super) fn contains_position(&self, position: usize) -> bool {
        self.mountain.contains_position(position)
    }
}

fn append_shape_recompute_index_trusted(
    old_num_leaves: usize,
    changed: &[ChangedMountain],
) -> usize {
    let old_shape_len = shape_len_for_num_leaves(old_num_leaves);
    debug_assert!(old_shape_len > 0);

    let Some(merged) = changed
        .iter()
        .map(|changed| changed.mountain)
        .find(|mountain| mountain.height > 0)
    else {
        return old_shape_len - 1;
    };

    let child_height = merged.height - 1;
    let left = ShapeMountain {
        start: merged.start,
        height: child_height,
    };
    let left_idx = shape_mountain_index_for_num_leaves(old_num_leaves, left)
        .expect("merged left child must be present in the old shape");
    if left_idx == 0 {
        return 0;
    }

    let old_split = shape_range_split_after_num_leaves(old_num_leaves, left_idx - 1)
        .expect("old split before merged child must exist");
    let previous_left =
        shape_mountain_at_index(old_num_leaves, left_idx - 1).expect("left neighbor must exist");
    let previous_previous_left = if left_idx >= 2 {
        Some(
            shape_mountain_at_index(old_num_leaves, left_idx - 2)
                .expect("previous left neighbor must exist")
                .height,
        )
    } else {
        None
    };
    let new_split = shape_range_split(previous_left.height, merged.height, previous_previous_left);
    if old_split == new_split { left_idx } else { left_idx - 1 }
}

fn append_changed_ranges_trusted(
    new_num_leaves: usize,
    suffix_start: usize,
    changed: &[ChangedMountain],
) -> AppendChangedRanges {
    let new_shape_len = shape_len_for_num_leaves(new_num_leaves);
    debug_assert!(!changed.is_empty());
    debug_assert!(changed.len() <= 2);
    debug_assert!(suffix_start < new_shape_len);

    let mut changed_indices = [0usize; 2];
    let mut changed_len = 0;
    for changed in changed {
        let idx = shape_mountain_index_for_num_leaves(new_num_leaves, changed.mountain)
            .expect("changed append mountain must exist in the new shape");
        debug_assert!(idx >= suffix_start);
        changed_indices[changed_len] = idx;
        changed_len += 1;
    }

    if changed_len == 2 && changed_indices[0] > changed_indices[1] {
        changed_indices.swap(0, 1);
    }
    debug_assert!(changed_len == 1 || changed_indices[0] != changed_indices[1]);
    debug_assert_eq!(changed_indices[changed_len - 1], new_shape_len - 1);

    let mut ranges = AppendChangedRanges::new();
    let mut start = suffix_start;
    for &end in &changed_indices[..changed_len] {
        debug_assert!(end >= start);
        ranges.push(start..end + 1).expect("append changes at most two ranges");
        start = end + 1;
    }
    debug_assert_eq!(start, new_shape_len);

    ranges
}

fn changed_root_for_range_trusted(
    new_num_leaves: usize,
    range: &Range<usize>,
    changed: &[ChangedMountain],
) -> Word {
    let changed_mountain = shape_mountain_at_index(new_num_leaves, range.end - 1)
        .expect("changed range must end at a mountain");
    changed
        .iter()
        .find(|changed| changed.mountain == changed_mountain)
        .expect("changed range must end at an append-changed mountain")
        .root
}

#[cfg(test)]
pub(super) fn append_shape_in_place(
    shape: &mut Vec<ShapeMountain>,
    old_num_leaves: usize,
    changed: &[ChangedMountain],
) -> Result<(), MmrError> {
    let leaf = ShapeMountain { start: old_num_leaves, height: 0 };
    let merged = changed
        .iter()
        .map(|changed| changed.mountain)
        .find(|mountain| mountain.height > 0);
    let leaf_expected = merged.is_none_or(|merged| !merged.contains_position(old_num_leaves));
    let expected_len = usize::from(merged.is_some()) + usize::from(leaf_expected);
    if changed.len() != expected_len
        || (leaf_expected && !changed.iter().any(|changed| changed.mountain == leaf))
        || changed.iter().any(|changed| {
            Some(changed.mountain) != merged && !(leaf_expected && changed.mountain == leaf)
        })
    {
        return Err(MmrError::InvalidUpdate);
    }

    let Some(merged) = merged else {
        shape.push(leaf);
        return Ok(());
    };

    let child_height = merged.height - 1;
    let left = ShapeMountain {
        start: merged.start,
        height: child_height,
    };
    let right = ShapeMountain {
        start: merged.start + (1usize << child_height),
        height: child_height,
    };
    let left_idx =
        shape_mountain_index_for_num_leaves(old_num_leaves, left).ok_or(MmrError::InvalidUpdate)?;
    if leaf_expected {
        let right_idx = left_idx + 1;
        let old_len = shape.len();
        if shape.get(right_idx).copied() != Some(right) {
            return Err(MmrError::InvalidUpdate);
        }

        shape[left_idx] = merged;
        if right_idx + 1 < old_len {
            shape.copy_within(right_idx + 1..old_len, right_idx);
        }
        shape[old_len - 1] = leaf;
    } else {
        if shape.get(left_idx).copied() != Some(left) || left_idx + 1 != shape.len() {
            return Err(MmrError::InvalidUpdate);
        }

        shape[left_idx] = merged;
    }

    Ok(())
}
