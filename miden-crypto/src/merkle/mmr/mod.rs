//! Merkle Mountain Range (MMR) data structures.

#[cfg(feature = "internal")]
pub mod belt;
#[cfg(not(feature = "internal"))]
pub(crate) mod belt;
mod delta;
mod error;
mod forest;
mod frontier;
mod full;
mod inorder;
mod partial;
mod peaks;
mod proof;

#[cfg(test)]
mod tests;

/// Returns the number of nodes represented by a forest bitmask.
///
/// `mask` is a forest-leaf mask (same encoding as [`Forest::num_leaves()`]): each set bit denotes
/// one peak/tree with leaf count `2^bit_position`.
fn nodes_from_mask(mask: usize) -> usize {
    Forest::new(mask).expect("mask must encode a valid forest").num_nodes()
}

// REEXPORTS
// ================================================================================================
pub use delta::MmrDelta;
pub use error::MmrError;
pub use forest::Forest;
pub use frontier::MerkleFrontier;
pub use full::Mmr;
pub use inorder::InOrderIndex;
pub use partial::PartialMmr;
pub use peaks::MmrPeaks;
pub use proof::{MmrPath, MmrProof};
