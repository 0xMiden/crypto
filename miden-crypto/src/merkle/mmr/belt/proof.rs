use alloc::vec::Vec;
use core::ops::Range;

use super::BeltSummary;
use super::shape::*;
use crate::{Word, hash::poseidon2::Poseidon2};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeltProof {
    pub(super) position: usize,
    pub(super) leaf: Word,
    pub(super) nodes: Vec<BeltProofNode>,
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
            || self.nodes.iter().zip(&steps).any(|(node, side)| node.side != *side)
        {
            return false;
        }

        let root =
            self.nodes
                .iter()
                .zip(&steps)
                .fold(self.leaf, |current, (node, side)| match side {
                    SiblingSide::Left => Poseidon2::merge(&[node.value, current]),
                    SiblingSide::Right => Poseidon2::merge(&[current, node.value]),
                });

        root == summary.commitment_root()
    }

    #[cfg(test)]
    pub(super) fn set_leaf_for_testing(&mut self, leaf: Word) {
        self.leaf = leaf;
    }

    #[cfg(test)]
    pub(super) fn set_position_for_testing(&mut self, position: usize) {
        self.position = position;
    }

    #[cfg(test)]
    pub(super) fn tamper_node_value_for_testing(&mut self, index: usize, value: Word) {
        self.nodes[index].value = value;
    }

    #[cfg(test)]
    pub(super) fn node_count_for_testing(&self) -> usize {
        self.nodes.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BeltProofNode {
    pub(super) value: Word,
    pub(super) side: SiblingSide,
}

pub(super) fn bagging_path_nodes(
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

    let prefix = bag_range(&peaks[range.start..mountain_idx]);
    nodes.push(BeltProofNode { value: prefix, side: SiblingSide::Left });
    for &peak in &peaks[mountain_idx + 1..range.end] {
        nodes.push(BeltProofNode { value: peak, side: SiblingSide::Right });
    }

    // Exclude the proven range root from the belt path.
    let range_root = |range: &Range<usize>| bag_range(&peaks[range.clone()]);
    let prefix_belt = bag_belt(&ranges[..range_idx].iter().map(range_root).collect::<Vec<_>>());
    nodes.push(BeltProofNode {
        value: prefix_belt,
        side: SiblingSide::Left,
    });
    for range in &ranges[range_idx + 1..] {
        nodes.push(BeltProofNode {
            value: range_root(range),
            side: SiblingSide::Right,
        });
    }

    nodes
}

pub(super) fn proof_steps_for_position(
    num_leaves: usize,
    position: usize,
) -> Option<Vec<SiblingSide>> {
    if position >= num_leaves {
        return None;
    }

    let shape = shape_mountains(num_leaves);
    let mountain_idx = shape_mountain_for_position(&shape, position)?;
    let mountain = shape[mountain_idx];

    let mut steps = balanced_tree_sides(mountain.height, position - mountain.start);

    let ranges = shape_ranges(&shape);
    let range_idx = ranges.iter().position(|range| range.contains(&mountain_idx))?;
    let range = ranges[range_idx].clone();

    steps.push(SiblingSide::Left);
    for _ in &shape[mountain_idx + 1..range.end] {
        steps.push(SiblingSide::Right);
    }

    steps.push(SiblingSide::Left);
    for _ in (range_idx + 1)..ranges.len() {
        steps.push(SiblingSide::Right);
    }

    Some(steps)
}
