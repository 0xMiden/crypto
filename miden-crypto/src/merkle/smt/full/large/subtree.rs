use alloc::vec::Vec;
use super::{InnerNode, NodeIndex, RpoDigest, SUBTREE_DEPTH};
use crate::utils::{Deserializable, DeserializationError};

/// Represents a complete 8-depth subtree that can be serialized into a single RocksDB entry.
#[derive(Debug, Clone)]
pub struct Subtree {
    pub root_index: NodeIndex,
    pub nodes: Vec<Option<InnerNode>>,
}

impl Subtree {
    pub const DEPTH: usize = 8;
    pub const NODE_COUNT: usize = (1 << Self::DEPTH) - 1; // 2^8 - 1 = 255

    pub fn new(root_index: NodeIndex) -> Self {
        Self {
            root_index,
            nodes: vec![None; Self::NODE_COUNT],
        }
    }

    pub fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        let old_value = self.nodes[local_index as usize].clone();
        self.nodes[local_index as usize] = Some(inner_node);
        old_value
    }

    pub fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode>  {
        let local_index = Self::global_to_local(index, self.root_index);
        let old_value = self.nodes[local_index as usize].clone();
        self.nodes[local_index as usize] = None;
        old_value
    }

    pub fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.nodes[local_index as usize].clone()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        const NODE_SIZE: usize = 64; // 32 bytes for left + 32 bytes for right
        const BITMASK_SIZE: usize = 32;

        // Count how many nodes are present to pre-allocate the exact size needed
        let present_nodes = self.nodes.iter().filter(|n| n.is_some()).count();
        let mut buf = Vec::with_capacity(BITMASK_SIZE + present_nodes * NODE_SIZE);

        // Create and write bitmask
        let mut bitmask = [0u8; BITMASK_SIZE];
        for (i, node) in self.nodes.iter().enumerate() {
            if node.is_some() {
                bitmask[i / 8] |= 1 << (i % 8);
            }
        }
        buf.extend_from_slice(&bitmask);

        // Write node data
        for node in &self.nodes {
            if let Some(InnerNode { left, right }) = node {
                buf.extend_from_slice(&left.as_bytes());
                buf.extend_from_slice(&right.as_bytes());
            }
        }

        buf
    }

    pub fn from_vec(root_index: NodeIndex, data: Vec<u8>) -> Result<Self, DeserializationError> {
        const NODE_SIZE: usize = 64; // 32 bytes for left + 32 bytes for right
        const BITMASK_SIZE: usize = 32;

        if data.len() < BITMASK_SIZE {
            return Err(DeserializationError::InvalidValue("Subtree data too short".into()));
        }

        let (bitmask, node_data) = data.split_at(BITMASK_SIZE);
        let mut nodes = vec![None; Self::NODE_COUNT];
        let mut cursor = 0;

        for (i, &byte) in bitmask.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 != 0 {
                    let node_start = cursor * NODE_SIZE;
                    let node_end = node_start + NODE_SIZE;
                    
                    if node_end > node_data.len() {
                        return Err(DeserializationError::InvalidValue("Subtree node data too short".into()));
                    }

                    let node_bytes = &node_data[node_start..node_end];
                    let left = RpoDigest::read_from_bytes(&node_bytes[..32])?;
                    let right = RpoDigest::read_from_bytes(&node_bytes[32..])?;
                    
                    nodes[i * 8 + bit] = Some(InnerNode { left, right });
                    cursor += 1;
                }
            }
        }

        Ok(Self { root_index, nodes })
    }

    fn global_to_local(global: NodeIndex, base: NodeIndex) -> u8 {
        assert!(global.depth() >= base.depth(), "Global depth is less than base depth = {}, global depth = {}", base.depth(), global.depth());
        let relative_depth = global.depth() - base.depth();
        let subtree_span = 1 << relative_depth;
    
        let relative_index = global.value() % subtree_span;
        (1 << relative_depth) - 1 + (relative_index as u8)
    }

    pub fn subtree_key(root_index: NodeIndex) -> Vec<u8> {
        let mut key = vec![b'S'];
        key.push(root_index.depth());
        key.extend_from_slice(&root_index.value().to_le_bytes());
        key
    }
    
    // TODO: decide if we should keep this
    #[allow(dead_code)]
    pub fn subtree_root_from_key(key: &[u8]) -> NodeIndex {
        assert!(key.len() == 10, "Invalid key length for subtree key");
        assert_eq!(key[0], b'S', "Invalid key prefix for subtree");
    
        let depth = key[1];
    
        let value_bytes: [u8; 8] = key[2..10]
            .try_into()
            .expect("Failed to parse value bytes from subtree key");
        let value = u64::from_le_bytes(value_bytes);
    
        NodeIndex::new(depth, value).unwrap()
    }

    pub fn find_subtree_root(node_index: NodeIndex) -> NodeIndex {
        let depth = node_index.depth();
        assert!(depth >= SUBTREE_DEPTH, "Depth too small for subtree");
    
        // First: find the base depth of the subtree
        let subtree_root_depth = depth - (depth % SUBTREE_DEPTH);
    
        // How much deeper is the node compared to the subtree root
        let relative_depth = depth - subtree_root_depth;
    
        // Shift value back up to the subtree root
        let base_value = node_index.value() >> relative_depth;
    
        NodeIndex::new(subtree_root_depth, base_value).unwrap()
    }
}