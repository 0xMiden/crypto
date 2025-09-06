use alloc::vec::Vec;

use super::{EmptySubtreeRoots, InnerNode, InnerNodeInfo, NodeIndex, SMT_DEPTH};
use crate::{
    Word,
    merkle::smt::{Map, full::concurrent::SUBTREE_DEPTH},
};

mod error;
pub use error::SubtreeError;

#[cfg(test)]
mod tests;

/// Represents a complete 8-depth subtree that is serialized into a single RocksDB entry.
///
/// ### What is stored
/// - `nodes` tracks only **non-empty inner nodes** of this subtree (i.e., nodes for which at least
///   one child differs from the canonical empty hash). Each entry stores an `InnerNode` (hash
///   pair).
///
/// ### Local index layout (how indices are computed)
/// - Indices are **subtree-local** and follow binary-heap (level-order) layout: `root = 0`;
///   children of `i` are at `2i+1` and `2i+2`.
/// - Equivalently, given a `(depth, value)` from the parent tree, the local index is obtained by
///   taking the node’s depth **relative to the subtree root** and its left-to-right position within
///   that level (offset by the total number of nodes in all previous levels).
///
/// ### Serialization (`to_vec` / `from_vec`)
/// - Uses a **512-bit bitmask** (2 bits per node) to mark non-empty left/right children, followed
///   by a packed stream of `Word` hashes for each set bit.
/// - Children equal to the canonical empty hash are omitted in the byte representation and
///   reconstructed on load using `EmptySubtreeRoots` and the child’s depth in the parent tree.
#[derive(Debug, Clone)]
pub struct Subtree {
    /// Index of this subtree's root in the parent SMT.
    root_index: NodeIndex,
    /// Inner nodes keyed by subtree-local index (binary-heap order).
    nodes: Map<u8, InnerNode>,
}

impl Subtree {
    const HASH_SIZE: usize = 32;
    const BITMASK_SIZE: usize = 64;
    const MAX_NODES: u8 = 255;
    const BITS_PER_NODE: usize = 2;

    pub fn new(root_index: NodeIndex) -> Self {
        Self { root_index, nodes: Map::new() }
    }

    pub fn root_index(&self) -> NodeIndex {
        self.root_index
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn insert_inner_node(
        &mut self,
        index: NodeIndex,
        inner_node: InnerNode,
    ) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes.insert(local_index, inner_node)
    }

    pub fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes.remove(&local_index)
    }

    pub fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes.get(&local_index).cloned()
    }

    /// Serializes this subtree into a compact byte representation.
    ///
    /// The encoding has two components:
    ///
    /// **Bitmask (512 bits)** — Each internal node (up to 255 total) is assigned 2 bits:
    /// one for the left child and one for the right child. A bit is set if the corresponding
    /// child differs from the canonical empty hash at its depth. This avoids storing empty
    /// children.
    ///
    /// **Hash data** — For every set bit in the mask, the corresponding 32-byte `Word` hash
    /// is appended to the data section. Hashes are written in breadth-first (local index)
    /// order, scanning children left-then-right.
    ///
    /// On deserialization, omitted children are reconstructed using `EmptySubtreeRoots`.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.len() * Self::HASH_SIZE);
        let mut bitmask = [0u8; Self::BITMASK_SIZE];

        for local_index in 0..Self::MAX_NODES {
            if let Some(node) = self.nodes.get(&local_index) {
                let bit_offset = (local_index as usize) * Self::BITS_PER_NODE;
                let node_depth_in_subtree = Self::local_index_to_depth(local_index);
                let child_depth = self.root_index.depth() + node_depth_in_subtree + 1;
                let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

                if node.left != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset);
                    data.extend_from_slice(&node.left.as_bytes());
                }

                if node.right != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset + 1);
                    data.extend_from_slice(&node.right.as_bytes());
                }
            }
        }

        let mut result = Vec::with_capacity(Self::BITMASK_SIZE + data.len());
        result.extend_from_slice(&bitmask);
        result.extend_from_slice(&data);
        result
    }

    #[inline]
    fn set_bit(bitmask: &mut [u8], bit_offset: usize) {
        bitmask[bit_offset / 8] |= 1 << (bit_offset % 8);
    }

    #[inline]
    fn get_bit(bitmask: &[u8], bit_offset: usize) -> bool {
        (bitmask[bit_offset / 8] >> (bit_offset % 8)) & 1 != 0
    }

    /// Deserializes a subtree from its compact byte representation.
    ///
    /// The first 512 bits form the bitmask, which indicates which child hashes
    /// are present for each internal node (2 bits per node). For every set bit,
    /// a `Word` hash is read sequentially from the data section.
    ///
    /// When a child bit is unset, the corresponding hash is reconstructed from
    /// `EmptySubtreeRoots` based on the child’s depth in the full tree.
    ///
    /// Errors are returned if the byte slice is too short, contains an unexpected
    /// number of hashes, or leaves unconsumed data at the end.
    pub fn from_vec(root_index: NodeIndex, data: &[u8]) -> Result<Self, SubtreeError> {
        if data.len() < Self::BITMASK_SIZE {
            return Err(SubtreeError::TooShort {
                found: data.len(),
                min: Self::BITMASK_SIZE,
            });
        }
        let (bitmask, hash_data) = data.split_at(Self::BITMASK_SIZE);
        let present_hashes: usize = bitmask.iter().map(|&byte| byte.count_ones() as usize).sum();
        if hash_data.len() != present_hashes * Self::HASH_SIZE {
            return Err(SubtreeError::BadHashLen {
                expected: present_hashes * Self::HASH_SIZE,
                found: hash_data.len(),
            });
        }

        let mut nodes = Map::new();
        let mut hash_chunks = hash_data.chunks_exact(Self::HASH_SIZE);

        // Process each potential node position
        for local_index in 0..Self::MAX_NODES {
            let bit_offset = (local_index as usize) * Self::BITS_PER_NODE;
            let has_left = Self::get_bit(bitmask, bit_offset);
            let has_right = Self::get_bit(bitmask, bit_offset + 1);

            if has_left || has_right {
                // Calculate depth for empty hash lookup
                let node_depth_in_subtree = Self::local_index_to_depth(local_index);
                let child_depth = root_index.depth() + node_depth_in_subtree + 1;
                let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

                // Get left child hash
                let left_hash = if has_left {
                    let hash_bytes = hash_chunks
                        .next()
                        .ok_or(SubtreeError::MissingLeft { index: local_index })?;
                    Word::try_from(hash_bytes)
                        .map_err(|_| SubtreeError::BadLeft { index: local_index })?
                } else {
                    empty_hash
                };

                // Get right child hash
                let right_hash = if has_right {
                    let hash_bytes = hash_chunks
                        .next()
                        .ok_or(SubtreeError::MissingRight { index: local_index })?;
                    Word::try_from(hash_bytes)
                        .map_err(|_| SubtreeError::BadRight { index: local_index })?
                } else {
                    empty_hash
                };

                let inner_node = InnerNode { left: left_hash, right: right_hash };
                nodes.insert(local_index, inner_node);
            }
        }

        // Ensure all hash data was consumed
        if hash_chunks.next().is_some() {
            return Err(SubtreeError::ExtraData);
        }

        Ok(Self { root_index, nodes })
    }

    fn global_to_local(global: NodeIndex, base: NodeIndex) -> u8 {
        assert!(
            global.depth() >= base.depth(),
            "Global depth is less than base depth = {}, global depth = {}",
            base.depth(),
            global.depth()
        );

        // Calculate the relative depth within the subtree
        let relative_depth = global.depth() - base.depth();
        // Calculate the base offset in a binary tree of given relative depth
        let base_offset = (1 << relative_depth) - 1;
        // Mask out the lower `relative_depth` bits to find the local position in the subtree
        let mask = (1 << relative_depth) - 1;
        let local_position = (global.value() & mask) as u8;
        base_offset + local_position
    }

    pub fn subtree_key(root_index: NodeIndex) -> [u8; 9] {
        let mut key = [0u8; 9];
        key[0] = root_index.depth();
        key[1..].copy_from_slice(&root_index.value().to_be_bytes());
        key
    }

    pub fn find_subtree_root(node_index: NodeIndex) -> NodeIndex {
        let depth = node_index.depth();
        if depth < SUBTREE_DEPTH {
            NodeIndex::root()
        } else {
            let subtree_root_depth = depth - (depth % SUBTREE_DEPTH);
            let relative_depth = depth - subtree_root_depth;
            let base_value = node_index.value() >> relative_depth;

            NodeIndex::new(subtree_root_depth, base_value).unwrap()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert local index to depth within subtree
    #[inline]
    const fn local_index_to_depth(local_index: u8) -> u8 {
        let n = local_index as u16 + 1;
        (u16::BITS as u8 - 1) - n.leading_zeros() as u8
    }

    pub fn iter_inner_node_info(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.values().map(|inner_node_ref| InnerNodeInfo {
            value: inner_node_ref.hash(),
            left: inner_node_ref.left,
            right: inner_node_ref.right,
        })
    }
}
