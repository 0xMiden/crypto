mod bit;
mod delta;
mod error;
mod forest;
mod full;
mod inorder;
mod partial;
mod peaks;
mod proof;

#[cfg(test)]
mod tests;

// REEXPORTS
// ================================================================================================
pub use delta::MmrDelta;
pub use error::MmrError;
pub use full::Mmr;
pub use inorder::InOrderIndex;
pub use partial::PartialMmr;
pub use peaks::MmrPeaks;
pub use proof::MmrProof;

use super::{Felt, Rpo256, Word};

// UTILITIES
// ===============================================================================================

/// Return the total number of nodes of a given forest
///
/// Panics:
///
/// This will panic if the forest has size greater than `usize::MAX / 2`
const fn nodes_in_forest(forest: usize) -> usize {
    // TODO: replace with forest.node_count()
    
    // - the size of a perfect binary tree is $2^{k+1}-1$ or $2*2^k-1$
    // - the forest represents the sum of $2^k$ so a single multiplication is necessary
    // - the number of `-1` is the same as the number of trees, which is the same as the number
    // bits set
    let tree_count = forest.count_ones() as usize;
    forest * 2 - tree_count
}
