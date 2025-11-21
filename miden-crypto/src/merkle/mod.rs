//! Data structures related to Merkle trees based on RPO256 hash function.
use core::fmt::{self, Display};

use super::{EMPTY_WORD, Felt, Word, ZERO, hash::rpo::Rpo256};

// SUBMODULES
// ================================================================================================

mod empty_roots;
mod error;
mod index;
mod merkle_tree;
mod node;
mod partial_mt;
mod path;
mod sparse_path;

/// Merkle Mountain Range (MMR) data structures.
pub mod mmr;

/// Sparse Merkle Tree (SMT) data structures.
pub mod smt;

/// Merkle store for efficiently storing multiple Merkle trees with common subtrees.
pub mod store;

// REEXPORTS - MERKLE TREE
// ================================================================================================

pub use empty_roots::EmptySubtreeRoots;
pub use error::MerkleError;
pub use index::NodeIndex;
pub use merkle_tree::{MerkleTree, path_to_text, tree_to_text};
// REEXPORTS - OTHER
// ================================================================================================
pub use node::InnerNodeInfo;
pub use partial_mt::PartialMerkleTree;
// REEXPORTS - PATHS
// ================================================================================================
pub use path::{MerklePath, MerkleProof, RootPath};
pub use sparse_path::SparseMerklePath;

impl<const DEPTH: u8> Display for smt::LeafIndex<DEPTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DEPTH={}, value={}", DEPTH, self.value())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> Word {
    Word::new([Felt::new(value), ZERO, ZERO, ZERO])
}

#[cfg(test)]
const fn int_to_leaf(value: u64) -> Word {
    Word::new([Felt::new(value), ZERO, ZERO, ZERO])
}
