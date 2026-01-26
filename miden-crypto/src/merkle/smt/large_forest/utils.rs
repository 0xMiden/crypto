//! Contains utility type aliases and functions for use as part of the SMT forest.

use crate::{
    Word,
    merkle::{NodeIndex, smt::full::SMT_DEPTH},
};
// TYPE ALIASES
// ================================================================================================

/// The mutation set used by the forest backends to provide reverse mutations that describe the
/// changes necessary to revert the tree to its previous state.
pub type MutationSet = crate::merkle::smt::MutationSet<SMT_DEPTH, Word, Word>;

// UTILITY FUNCTIONS
// ================================================================================================

/// Gets the index of the sibling ot the provided `node` that becomes part of the merkle path.
///
/// # Panics
///
/// - If somehow the resultant node index is not within bounds.
#[allow(unused)] // Temporary
pub fn aux_node_index(node: &NodeIndex) -> NodeIndex {
    if node.is_value_odd() {
        NodeIndex::new(node.depth(), node.value() - 1).expect("Node index was not in bounds")
    } else {
        NodeIndex::new(node.depth(), node.value() + 1).expect("Node index was not in bounds")
    }
}
