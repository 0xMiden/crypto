use alloc::vec::Vec;

use super::{InnerNode, InnerNodeInfo, NodeIndex, SUBTREE_DEPTH};
use crate::utils::{Deserializable, DeserializationError};

#[cfg(test)]
mod tests;

const MAX_SIZE: usize = (1 << SUBTREE_DEPTH) - 1;

/// Represents a complete 8-depth subtree that can be serialized into a single RocksDB entry.
#[derive(Debug, Clone)]
pub struct Subtree {
    root_index: NodeIndex,
    nodes: [Option<InnerNode>; MAX_SIZE],
}

impl Subtree {
    const NODE_SIZE: usize = 64;
    const BITMASK_SIZE: usize = 32;

    pub fn new(root_index: NodeIndex) -> Self {
        Self {
            root_index,
            nodes: [const { None }; MAX_SIZE],
        }
    }

    pub fn root_index(&self) -> NodeIndex {
        self.root_index
    }

    pub fn len(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_some()).count()
    }

    pub fn insert_inner_node(
        &mut self,
        index: NodeIndex,
        inner_node: InnerNode,
    ) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes[local_index as usize].replace(inner_node)
    }

    pub fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes[local_index as usize].take()
    }

    pub fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes[local_index as usize].clone()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        // Create and write bitmask
        let mut bitmask = [0u8; Self::BITMASK_SIZE];
        let mut present_nodes = 0;
        for (_local_index, node) in self.nodes.iter().enumerate() {
            if node.is_some() {
                bitmask[_local_index / 8] |= 1 << (_local_index % 8);
                present_nodes += 1;
            }
        }
        // Pre-allocate the exact size needed
        let mut buf = Vec::with_capacity(Self::BITMASK_SIZE + present_nodes * Self::NODE_SIZE);
        buf.extend_from_slice(&bitmask);

        // Write node data in order
        for node in self.nodes.iter().flatten() {
            buf.extend_from_slice(&node.left.as_bytes());
            buf.extend_from_slice(&node.right.as_bytes());
        }

        buf
    }

    pub fn from_vec(root_index: NodeIndex, data: &[u8]) -> Result<Self, DeserializationError> {
        if data.len() < Self::BITMASK_SIZE {
            return Err(DeserializationError::InvalidValue("Subtree data too short".into()));
        }
        let (bitmask, node_data) = data.split_at(Self::BITMASK_SIZE);
        let present_nodes: usize = bitmask.iter().map(|&byte| byte.count_ones() as usize).sum();
        if node_data.len() != present_nodes * Self::NODE_SIZE {
            return Err(DeserializationError::InvalidValue("Invalid node data length".into()));
        }

        let mut nodes = [const { None }; MAX_SIZE];
        let mut node_data_chunks = node_data.chunks_exact(Self::NODE_SIZE);
        bitmask
            .iter()
            .enumerate()
            .flat_map(|(byte_idx, &byte_val)| {
                (0..8_u8).filter_map(move |bit_pos_in_byte| {
                    if (byte_val >> bit_pos_in_byte) & 1 != 0 {
                        let local_index = (byte_idx as u8 * 8) + bit_pos_in_byte;
                        Some(local_index)
                    } else {
                        None
                    }
                })
            })
            .try_for_each(|local_index| -> Result<(), DeserializationError> {
                let node_bytes = node_data_chunks.next().ok_or_else(|| {
                    DeserializationError::InvalidValue(
                        "Bitmask indicates more nodes than present in node_data".into(),
                    )
                })?;

                let node = InnerNode::read_from_bytes(node_bytes)?;
                nodes[local_index as usize].replace(node);
                Ok(())
            })?;

        // Ensure all expected node data was consumed
        if node_data_chunks.next().is_some() {
            return Err(DeserializationError::InvalidValue(
                "Node data is longer than indicated by the bitmask".into(),
            ));
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

    pub fn iter_inner_node_info(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.iter().filter_map(|inner_node_ref| {
            inner_node_ref.as_ref().map(|inner_node| InnerNodeInfo {
                value: inner_node.hash(),
                left: inner_node.left,
                right: inner_node.right,
            })
        })
    }
}
