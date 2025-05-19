mod bit;
mod delta;
mod error;
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

/// Given a 0-indexed leaf position and the current forest, return the tree number responsible for
/// the position.
///
/// Note:
/// The result is a tree position `p`, it has the following interpretations. $p+1$ is the depth of
/// the tree. Because the root element is not part of the proof, $p$ is the length of the
/// authentication path. $2^p$ is equal to the number of leaves in this particular tree. and
/// $2^(p+1)-1$ corresponds to size of the tree.
const fn leaf_to_corresponding_tree(pos: usize, forest: usize) -> Option<u32> {
    if pos >= forest {
        None
    } else {
        // - each bit in the forest is a unique tree and the bit position its power-of-two size
        // - each tree owns a consecutive range of positions equal to its size from left-to-right
        // - this means the first tree owns from `0` up to the `2^k_0` first positions, where `k_0`
        //   is the highest true bit position, the second tree from `2^k_0 + 1` up to `2^k_1` where
        //   `k_1` is the second highest bit, so on.
        // - this means the highest bits work as a category marker, and the position is owned by the
        //   first tree which doesn't share a high bit with the position
        let before = forest & pos;
        let after = forest ^ before;
        let tree = after.ilog2();

        Some(tree)
    }
}

/// Return the total number of nodes of a given forest
///
/// Panics:
///
/// This will panic if the forest has size greater than `usize::MAX / 2`
const fn nodes_in_forest(forest: usize) -> usize {
    // - the size of a perfect binary tree is $2^{k+1}-1$ or $2*2^k-1$
    // - the forest represents the sum of $2^k$ so a single multiplication is necessary
    // - the number of `-1` is the same as the number of trees, which is the same as the number
    // bits set
    let tree_count = forest.count_ones() as usize;
    forest * 2 - tree_count
}
