//! Data structures related to Merkle trees based on RPO256 hash function.
use core::fmt::{self, Display};

use super::{EMPTY_WORD, Felt, Word, ZERO, hash::rpo::Rpo256};

// REEXPORTS
// ================================================================================================

mod empty_roots;
pub use empty_roots::EmptySubtreeRoots;

mod index;
pub use index::NodeIndex;

mod merkle_tree;
pub use merkle_tree::{MerkleTree, path_to_text, tree_to_text};

mod path;
pub use path::{MerklePath, MerkleProof, RootPath};

mod sparse_path;
pub use sparse_path::SparseMerklePath;

mod smt;
pub use smt::{
    InnerNode, LeafIndex, MAX_LEAF_ENTRIES, MutationSet, NodeMutation, PartialSmt, SMT_DEPTH,
    SMT_MAX_DEPTH, SMT_MIN_DEPTH, SimpleSmt, SimpleSmtProof, Smt, SmtForest, SmtLeaf, SmtLeafError,
    SmtProof, SmtProofError,
};
#[cfg(feature = "concurrent")]
pub use smt::{
    LargeSmt, LargeSmtError, MemoryStorage, SmtStorage, StorageUpdateParts, StorageUpdates, Subtree,
};
#[cfg(feature = "rocksdb")]
pub use smt::{RocksDbConfig, RocksDbStorage};
#[cfg(feature = "internal")]
pub use smt::{SubtreeLeaf, build_subtree_for_bench};

mod mmr;
pub use mmr::{
    Forest, InOrderIndex, Mmr, MmrDelta, MmrError, MmrPath, MmrPeaks, MmrProof, PartialMmr,
};

mod store;
pub use store::{MerkleStore, StoreNode};

mod node;
pub use node::InnerNodeInfo;

mod partial_mt;
pub use partial_mt::PartialMerkleTree;

mod error;
pub use error::MerkleError;

impl<const DEPTH: u8> Display for LeafIndex<DEPTH> {
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
