use thiserror::Error;

use super::{NodeIndex, Word};

/// Errors that can occur when constructing or verifying a Merkle tree.
#[derive(Debug, Error)]
pub enum MerkleError {
    /// The computed root does not match the expected root.
    #[error("expected merkle root {expected_root} found {actual_root}")]
    ConflictingRoots {
        /// The expected Merkle root.
        expected_root: Word,
        /// The actual root that was computed.
        actual_root: Word,
    },

    /// The provided Merkle tree depth is too small.
    #[error("provided merkle tree depth {0} is too small")]
    DepthTooSmall(u8),

    /// The provided Merkle tree depth is too big.
    #[error("provided merkle tree depth {0} is too big")]
    DepthTooBig(u64),

    /// Multiple values were provided for the same Merkle tree index.
    #[error("multiple values provided for merkle tree index {0}")]
    DuplicateValuesForIndex(u64),

    /// The node index value is invalid for the specified depth.
    #[error("node index value {value} is not valid for depth {depth}")]
    InvalidNodeIndex {
        /// The depth of the Merkle tree.
        depth: u8,
        /// The invalid node index value.
        value: u64,
    },

    /// Provided node index depth does not match the expected depth.
    #[error("provided node index depth {provided} does not match expected depth {expected}")]
    InvalidNodeIndexDepth {
        /// Expected tree depth.
        expected: u8,
        /// Provided (actual) tree depth.
        provided: u8,
    },

    /// The depth of a Merkle subtree exceeds the depth of the full tree.
    #[error("merkle subtree depth {subtree_depth} exceeds merkle tree depth {tree_depth}")]
    SubtreeDepthExceedsDepth {
        /// Depth of the subtree.
        subtree_depth: u8,
        /// Depth of the full Merkle tree.
        tree_depth: u8,
    },

    /// The number of entries exceeds the allowed maximum.
    #[error("number of entries in the merkle tree exceeds the maximum of {0}")]
    TooManyEntries(usize),

    /// The node index is not found in the tree.
    #[error("node index `{0}` not found in the tree")]
    NodeIndexNotFoundInTree(NodeIndex),

    /// The specified node is not found in the store.
    #[error("node {0:?} with index `{1}` not found in the store")]
    NodeIndexNotFoundInStore(
        /// The node value.
        Word,
        /// The node index.
        NodeIndex,
    ),

    /// The number of leaves is not a power of two.
    #[error("number of provided merkle tree leaves {0} is not a power of two")]
    NumLeavesNotPowerOfTwo(usize),

    /// The specified Merkle root is not present in the store.
    #[error("root {0:?} is not in the store")]
    RootNotInStore(Word),

    /// The Merkle path for the given key is not tracked in the partial SMT.
    #[error(
        "partial smt does not track the merkle path for key {0} so updating it would produce a different root compared to the same update in the full tree"
    )]
    UntrackedKey(Word),
}
