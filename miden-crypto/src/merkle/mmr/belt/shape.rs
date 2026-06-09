use alloc::vec::Vec;
use core::ops::Range;

use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SiblingSide {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HashIndex(pub(super) usize);

pub(super) fn leaf_hash_index(position: usize) -> HashIndex {
    HashIndex(2 * (position + 1) + 1)
}

pub(super) fn parent_hash_index(child: HashIndex) -> HashIndex {
    let span = 1usize << (child.0.trailing_zeros() as usize + 2);
    HashIndex(child.0 + child.0 % span)
}

#[cfg(test)]
pub(super) fn hash_children(parent: HashIndex) -> (HashIndex, HashIndex) {
    debug_assert!(parent.0 % 2 == 0);
    let span = 1usize << (parent.0.trailing_zeros() as usize - 1);
    (HashIndex(parent.0 - 3 * span), HashIndex(parent.0 - span))
}

pub(super) fn node_hash_index(start: usize, height: usize) -> HashIndex {
    // Lemma 24 closed form for the node covering `[start, start + 2^height)`.
    HashIndex((2 * (start >> height) + 3) << height)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ShapeMountain {
    pub(super) start: usize,
    pub(super) height: usize,
}

impl ShapeMountain {
    pub(super) fn size(&self) -> usize {
        1usize << self.height
    }

    pub(super) fn contains_position(&self, position: usize) -> bool {
        position >= self.start && position < self.start + self.size()
    }
}

pub(super) fn shape_mountains(num_leaves: usize) -> Vec<ShapeMountain> {
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

pub(super) fn shape_mountain_for_position(
    mountains: &[ShapeMountain],
    position: usize,
) -> Option<usize> {
    mountains
        .iter()
        .position(|mountain| position < mountain.start + mountain.size())
}

#[cfg(test)]
pub(super) fn shape_mountain_index(
    mountains: &[ShapeMountain],
    target: ShapeMountain,
) -> Option<usize> {
    mountains.iter().position(|&mountain| mountain == target)
}

pub(super) fn shape_mountain_index_for_num_leaves(
    num_leaves: usize,
    target: ShapeMountain,
) -> Option<usize> {
    if num_leaves == 0 {
        return None;
    }

    let bits = num_leaves + 1;
    let num_mountains = bits.ilog2() as usize;

    let mut index = None;
    if target.height < num_mountains && (bits >> target.height) & 1 == 0 {
        index = shape_mountain_index_candidate(bits, num_mountains, target.height, target);
    }
    if index.is_none() && target.height > 0 {
        let position = target.height - 1;
        if position < num_mountains && (bits >> position) & 1 == 1 {
            index = shape_mountain_index_candidate(bits, num_mountains, position, target);
        }
    }

    index
}

pub(super) fn shape_mountain_index_candidate(
    bits: usize,
    num_mountains: usize,
    position: usize,
    target: ShapeMountain,
) -> Option<usize> {
    let bit = (bits >> position) & 1;
    let height = position + bit;
    if height != target.height {
        return None;
    }

    let lower_mask = (1usize << (position + 1)) - 1;
    let mountain_mask = (1usize << num_mountains) - 1;
    let higher_mask = mountain_mask ^ lower_mask;
    let base = (1usize << num_mountains) - (1usize << (position + 1));
    let start = base + (bits & higher_mask);
    if start != target.start {
        return None;
    }

    Some(num_mountains - 1 - position)
}

pub(super) fn shape_len_for_num_leaves(num_leaves: usize) -> usize {
    if num_leaves == 0 {
        0
    } else {
        (num_leaves + 1).ilog2() as usize
    }
}

pub(super) fn shape_mountain_at_index(num_leaves: usize, index: usize) -> Option<ShapeMountain> {
    if num_leaves == 0 {
        return None;
    }

    let bits = num_leaves + 1;
    let num_mountains = bits.ilog2() as usize;
    if index >= num_mountains {
        return None;
    }

    let position = num_mountains - 1 - index;
    let bit = (bits >> position) & 1;
    let height = position + bit;
    let lower_mask = (1usize << (position + 1)) - 1;
    let mountain_mask = (1usize << num_mountains) - 1;
    let higher_mask = mountain_mask ^ lower_mask;
    let base = (1usize << num_mountains) - (1usize << (position + 1));
    let start = base + (bits & higher_mask);

    Some(ShapeMountain { start, height })
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn shape_range_index_for_mountain(
    ranges: &[Range<usize>],
    mountain_idx: usize,
) -> Option<usize> {
    ranges.iter().position(|range| range.contains(&mountain_idx))
}

pub(super) fn shape_range_index_for_num_leaves(
    num_leaves: usize,
    mountain_idx: usize,
) -> Option<usize> {
    let shape_len = shape_len_for_num_leaves(num_leaves);
    if mountain_idx >= shape_len {
        return None;
    }

    let bits = num_leaves + 1;
    let split_mask = bits & (!(bits << 1) | !(bits >> 1));
    let mountain_mask = (1usize << shape_len) - 1;
    let prefix_mask = (1usize << (shape_len - mountain_idx)) - 1;

    Some((split_mask & (mountain_mask ^ prefix_mask)).count_ones() as usize)
}

pub(super) fn shape_ranges(mountains: &[ShapeMountain]) -> Vec<Range<usize>> {
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

pub(super) fn shape_range_split_after(mountains: &[ShapeMountain], idx: usize) -> bool {
    shape_range_split(
        mountains[idx].height,
        mountains[idx + 1].height,
        (idx > 0).then(|| mountains[idx - 1].height),
    )
}

pub(super) fn shape_range_split_after_num_leaves(num_leaves: usize, idx: usize) -> Option<bool> {
    Some(shape_range_split(
        shape_mountain_at_index(num_leaves, idx)?.height,
        shape_mountain_at_index(num_leaves, idx + 1)?.height,
        if idx == 0 {
            None
        } else {
            Some(shape_mountain_at_index(num_leaves, idx - 1)?.height)
        },
    ))
}

pub(super) fn shape_range_split(left: usize, right: usize, previous_left: Option<usize>) -> bool {
    let drops_by_two = left == right + 2;
    let left_is_right_member_of_mergeable_pair = previous_left == Some(left);

    drops_by_two || left_is_right_member_of_mergeable_pair
}

pub(super) fn sibling_and_parent_start(start: usize, height: usize) -> (SiblingSide, usize, usize) {
    let span = 1usize << height;
    if (start >> height) & 1 == 0 {
        (SiblingSide::Right, start + span, start)
    } else {
        (SiblingSide::Left, start - span, start - span)
    }
}

pub(super) fn climb_to_peak(
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

pub(super) fn bag_range(peaks: &[Word]) -> Word {
    peaks.iter().fold(EMPTY_WORD, |acc, &peak| Poseidon2::merge(&[acc, peak]))
}

pub(super) fn bag_belt(range_roots: &[Word]) -> Word {
    range_roots.iter().fold(EMPTY_WORD, |acc, &root| Poseidon2::merge(&[acc, root]))
}

pub(super) fn common_peak_prefix_len(from_num_leaves: usize, to_num_leaves: usize) -> usize {
    let from_shape = shape_mountains(from_num_leaves);
    let to_shape = shape_mountains(to_num_leaves);
    common_peak_prefix_len_from_shapes(&from_shape, &to_shape)
}

pub(super) fn common_peak_prefix_len_from_shapes(
    from_shape: &[ShapeMountain],
    to_shape: &[ShapeMountain],
) -> usize {
    from_shape
        .iter()
        .zip(to_shape.iter())
        .take_while(|(from, to)| from.start == to.start && from.height == to.height)
        .count()
}

pub(super) fn sibling_side(is_left_child: bool) -> SiblingSide {
    if is_left_child {
        SiblingSide::Right
    } else {
        SiblingSide::Left
    }
}

pub(super) fn balanced_tree_sides(height: usize, mut local_position: usize) -> Vec<SiblingSide> {
    let mut sides = Vec::with_capacity(height);
    for _ in 0..height {
        sides.push(sibling_side(local_position & 1 == 0));
        local_position >>= 1;
    }
    sides
}
