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
pub use path::{MerklePath, RootPath, ValuePath};

mod sparse_path;
pub use sparse_path::{SparseMerklePath, SparseValuePath};

mod smt;
pub use smt::{
    InnerNode, LeafIndex, MutationSet, NodeMutation, PartialSmt, SMT_DEPTH, SMT_MAX_DEPTH,
    SMT_MIN_DEPTH, SimpleSmt, Smt, SmtLeaf, SmtLeafError, SmtProof, SmtProofError,
};
#[cfg(feature = "internal")]
pub use smt::{SubtreeLeaf, build_subtree_for_bench};

mod mmr;
pub use mmr::{InOrderIndex, Mmr, MmrDelta, MmrError, MmrPeaks, MmrProof, PartialMmr};

mod store;
pub use store::{DefaultMerkleStore, MerkleStore, RecordingMerkleStore, StoreNode};

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

// Used for doctests in `merkle::mmr::mountain_range`; #[cfg(doctest)] doesn't help here:
// https://github.com/rust-lang/rust/issues/67295.
#[doc(hidden)]
pub use mmr::Forest;

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
