use alloc::string::{String, ToString};

use thiserror::Error;

use super::{MAX_LEAF_ENTRIES, NodeIndex, Word};

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("expected merkle root {expected_root} found {actual_root}")]
    ConflictingRoots { expected_root: Word, actual_root: Word },
    #[error("provided merkle tree depth {0} is too small")]
    DepthTooSmall(u8),
    #[error("provided merkle tree depth {0} is too big")]
    DepthTooBig(u64),
    #[error("multiple values provided for merkle tree index {0}")]
    DuplicateValuesForIndex(u64),
    #[error("node index value {value} is not valid for depth {depth}")]
    InvalidNodeIndex { depth: u8, value: u64 },
    #[error("provided node index depth {provided} does not match expected depth {expected}")]
    InvalidNodeIndexDepth { expected: u8, provided: u8 },
    #[error("provided node list should have a minimum length of {0}")]
    InvalidPathLength(usize),
    #[error("merkle subtree depth {subtree_depth} exceeds merkle tree depth {tree_depth}")]
    SubtreeDepthExceedsDepth { subtree_depth: u8, tree_depth: u8 },
    #[error("number of entries in the merkle tree exceeds the maximum of 2^{0}")]
    TooManyEntries(u8),
    #[error("number of entries in a leaf ({actual}) exceeds the maximum of ({MAX_LEAF_ENTRIES})")]
    TooManyLeafEntries { actual: usize },
    #[error("node index `{0}` not found in the tree")]
    NodeIndexNotFoundInTree(NodeIndex),
    #[error("node {0:?} with index `{1}` not found in the store")]
    NodeIndexNotFoundInStore(Word, NodeIndex),
    #[error("number of provided merkle tree leaves {0} is not a power of two")]
    NumLeavesNotPowerOfTwo(usize),
    #[error("root {0:?} is not in the store")]
    RootNotInStore(Word),
    #[error("partial smt does not track the merkle path for key {0}")]
    UntrackedKey(Word),
    #[error("internal error: {0}")]
    InternalError(String),
}

#[cfg(feature = "concurrent")]
impl From<crate::merkle::LargeSmtError> for MerkleError {
    fn from(err: crate::merkle::LargeSmtError) -> Self {
        match err {
            crate::merkle::LargeSmtError::Merkle(me) => me,
            crate::merkle::LargeSmtError::Storage(se) => MerkleError::InternalError(se.to_string()),
        }
    }
}
