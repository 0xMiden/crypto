use alloc::vec::Vec;

use super::{EmptySubtreeRoots, InnerNode, InnerNodeInfo, NodeIndex, SMT_DEPTH};
use crate::{Word, merkle::smt::full::concurrent::SUBTREE_DEPTH};

mod error;
pub use error::SubtreeError;

#[cfg(test)]
mod tests;

/// Represents a complete 8-depth subtree that is serialized into a single RocksDB entry.
///
/// ### What is stored
/// - `non_empty_node_bits` is a 256-bit bitmask (4 x u64) where each bit indicates whether the
///   corresponding node exists (i.e., differs from the canonical empty state).
/// - `nodes` stores the left and right child hashes for each existing node, packed in order of set
///   bits. For each set bit at position `i`, two consecutive Words (left, right) are stored.
///
/// ### Local index layout (how indices are computed)
/// - Indices are **subtree-local** and follow binary-heap (level-order) layout: `root = 0`;
///   children of `i` are at `2i+1` and `2i+2`.
/// - Equivalently, given a `(depth, value)` from the parent tree, the local index is obtained by
///   taking the node's depth **relative to the subtree root** and its left-to-right position within
///   that level (offset by the total number of nodes in all previous levels).
///
/// ### Serialization (`to_vec` / `from_vec`)
/// - Uses a **512-bit bitmask** (2 bits per node) to mark non-empty left/right children, followed
///   by a packed stream of `Word` hashes for each set bit.
/// - Children equal to the canonical empty hash are omitted in the byte representation and
///   reconstructed on load using `EmptySubtreeRoots` and the child's depth in the parent tree.
#[derive(Debug, Clone)]
pub struct Subtree {
    /// Index of this subtree's root in the parent SMT.
    root_index: NodeIndex,
    /// Bitmask indicating which nodes exist (256 bits for local indices 0-255).
    non_empty_node_bits: [u64; 4],
    /// Child hashes for existing nodes, stored as pairs (left, right) in order of set bits.
    nodes: Vec<Word>,
}

impl Subtree {
    const HASH_SIZE: usize = 32;
    const BITMASK_SIZE: usize = 64;
    const MAX_NODES: u8 = 255;
    const BITS_PER_NODE: usize = 2;

    pub fn new(root_index: NodeIndex) -> Self {
        Self {
            root_index,
            non_empty_node_bits: [0u64; 4],
            nodes: Vec::new(),
        }
    }

    /// Creates a subtree from an iterator of nodes.
    ///
    /// This is more efficient than calling `insert_inner_node` repeatedly,
    /// as it builds the bitmask and node vector in a single pass after sorting.
    pub fn from_nodes(
        root_index: NodeIndex,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) -> Self {
        // Convert to local indices and collect
        let mut local_nodes: Vec<(u8, InnerNode)> = nodes
            .into_iter()
            .map(|(index, node)| (Self::global_to_local(index, root_index), node))
            .collect();

        // Sort by local index for sequential Vec building
        local_nodes.sort_unstable_by_key(|(local_idx, _)| *local_idx);

        // Build bitmask and nodes Vec in one pass
        let mut subtree = Self::new(root_index);
        subtree.nodes.reserve(local_nodes.len() * 2);

        for (local_index, inner_node) in local_nodes {
            subtree.set_node_bit(local_index, true);
            subtree.nodes.push(inner_node.left);
            subtree.nodes.push(inner_node.right);
        }

        subtree
    }

    pub fn root_index(&self) -> NodeIndex {
        self.root_index
    }

    pub fn len(&self) -> usize {
        self.non_empty_node_bits.iter().map(|&bits| bits.count_ones() as usize).sum()
    }

    pub fn insert_inner_node(
        &mut self,
        index: NodeIndex,
        inner_node: InnerNode,
    ) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        let was_present = self.is_node_present(local_index);

        if was_present {
            // Node exists - replace in place
            let position = self.node_position(local_index);
            let old_left = self.nodes[position * 2];
            let old_right = self.nodes[position * 2 + 1];
            self.nodes[position * 2] = inner_node.left;
            self.nodes[position * 2 + 1] = inner_node.right;
            Some(InnerNode { left: old_left, right: old_right })
        } else {
            // Node doesn't exist - insert at the correct position
            let position = self.node_position(local_index);
            self.set_node_bit(local_index, true);
            self.nodes.insert(position * 2, inner_node.left);
            self.nodes.insert(position * 2 + 1, inner_node.right);
            None
        }
    }

    pub fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);

        if !self.is_node_present(local_index) {
            return None;
        }

        let position = self.node_position(local_index);
        let old_left = self.nodes[position * 2];
        let old_right = self.nodes[position * 2 + 1];

        self.set_node_bit(local_index, false);
        self.nodes.remove(position * 2 + 1);
        self.nodes.remove(position * 2);

        Some(InnerNode { left: old_left, right: old_right })
    }

    pub fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);

        if !self.is_node_present(local_index) {
            return None;
        }

        let position = self.node_position(local_index);
        Some(InnerNode {
            left: self.nodes[position * 2],
            right: self.nodes[position * 2 + 1],
        })
    }

    /// Returns true if a node exists at the given local index.
    #[inline]
    fn is_node_present(&self, local_index: u8) -> bool {
        let word_idx = (local_index / 64) as usize;
        let bit_idx = local_index % 64;
        (self.non_empty_node_bits[word_idx] >> bit_idx) & 1 != 0
    }

    /// Sets or clears the bit for the given local index.
    #[inline]
    fn set_node_bit(&mut self, local_index: u8, present: bool) {
        let word_idx = (local_index / 64) as usize;
        let bit_idx = local_index % 64;
        if present {
            self.non_empty_node_bits[word_idx] |= 1u64 << bit_idx;
        } else {
            self.non_empty_node_bits[word_idx] &= !(1u64 << bit_idx);
        }
    }

    /// Returns the position in the `nodes` Vec for the given local index.
    /// This is the count of set bits before this index in the bitmask.
    #[inline]
    fn node_position(&self, local_index: u8) -> usize {
        let mut count = 0usize;
        let full_words = (local_index / 64) as usize;
        let remaining_bits = local_index % 64;

        // Count all bits in full words
        for i in 0..full_words {
            count += self.non_empty_node_bits[i].count_ones() as usize;
        }

        // Count bits in the partial word up to (but not including) the target bit
        if remaining_bits > 0 {
            let mask = (1u64 << remaining_bits) - 1;
            count += (self.non_empty_node_bits[full_words] & mask).count_ones() as usize;
        }

        count
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
            if self.is_node_present(local_index) {
                let position = self.node_position(local_index);
                let left = self.nodes[position * 2];
                let right = self.nodes[position * 2 + 1];

                let bit_offset = (local_index as usize) * Self::BITS_PER_NODE;
                let node_depth_in_subtree = Self::local_index_to_depth(local_index);
                let child_depth = self.root_index.depth() + node_depth_in_subtree + 1;
                let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

                if left != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset);
                    data.extend_from_slice(&left.as_bytes());
                }

                if right != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset + 1);
                    data.extend_from_slice(&right.as_bytes());
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
    /// `EmptySubtreeRoots` based on the child's depth in the full tree.
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

        let mut non_empty_node_bits = [0u64; 4];
        let mut nodes = Vec::new();
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

                // Set the bit in the bitmask
                let word_idx = (local_index / 64) as usize;
                let bit_idx = local_index % 64;
                non_empty_node_bits[word_idx] |= 1u64 << bit_idx;

                // Store the child hashes
                nodes.push(left_hash);
                nodes.push(right_hash);
            }
        }

        // Ensure all hash data was consumed
        if hash_chunks.next().is_some() {
            return Err(SubtreeError::ExtraData);
        }

        Ok(Self { root_index, non_empty_node_bits, nodes })
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
        self.non_empty_node_bits.iter().all(|&bits| bits == 0)
    }

    /// Returns an iterator over all (NodeIndex, InnerNode) pairs in this subtree.
    pub fn iter_nodes(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        (0..Self::MAX_NODES)
            .filter(|&local_index| self.is_node_present(local_index))
            .map(|local_index| {
                let position = self.node_position(local_index);
                let inner_node = InnerNode {
                    left: self.nodes[position * 2],
                    right: self.nodes[position * 2 + 1],
                };
                let global_index = Self::local_to_global(local_index, self.root_index);
                (global_index, inner_node)
            })
    }

    /// Converts a local subtree index back to a global NodeIndex.
    fn local_to_global(local_index: u8, root_index: NodeIndex) -> NodeIndex {
        let local_depth = Self::local_index_to_depth(local_index);
        let global_depth = root_index.depth() + local_depth;

        // Calculate position within the level
        let level_start = (1u8 << local_depth) - 1;
        let position_in_level = local_index - level_start;

        // Global value is root's value shifted left by local_depth, plus position
        let global_value = (root_index.value() << local_depth) | (position_in_level as u64);

        NodeIndex::new_unchecked(global_depth, global_value)
    }

    /// Convert local index to depth within subtree
    #[inline]
    const fn local_index_to_depth(local_index: u8) -> u8 {
        let n = local_index as u16 + 1;
        (u16::BITS as u8 - 1) - n.leading_zeros() as u8
    }

    pub fn iter_inner_node_info(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        (0..Self::MAX_NODES)
            .filter(|&local_index| self.is_node_present(local_index))
            .map(|local_index| {
                let position = self.node_position(local_index);
                let left = self.nodes[position * 2];
                let right = self.nodes[position * 2 + 1];
                let inner_node = InnerNode { left, right };
                InnerNodeInfo { value: inner_node.hash(), left, right }
            })
    }
}
