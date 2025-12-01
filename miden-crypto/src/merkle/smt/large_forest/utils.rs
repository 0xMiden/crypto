//! This module contains a variety of useful functions and type aliases that do not really have any
//! other place to live.

// CONSTANTS
// ================================================================================================

use core::fmt::{Display, Formatter};

use crate::merkle::NodeIndex;

/// The maximum number of levels that can be stored in a given subtree for a tree with depth 64.
///
/// Simply put, it must never include the leaves level, and hence is one less than that depth.
pub const MAX_NUM_SUBTREE_LEVELS: u8 = 63;

// TYPE ALIASES
// ================================================================================================

/// The type of linear indexes in the in-memory tree prefix.
///
/// It is assumed to be indexing into a linear container of nodes which contains `2.pow(depth + 1)`
/// entries laid out as follows:
///
/// - Index 0 is unused, containing a sentinel value.
/// - Index 1 contains the root of the tree.
/// - For a node at index `i`, the left child is found at index `2 * i` and the right child at index
///   `2 * i + 1`.
pub type LinearIndex = u64;

// SUBTREE LEVELS
// ================================================================================================

/// The number of levels in a tree.
///
/// # Invariants
///
/// Any instance of this type should see that the following properties hold:
///
/// - The root is a level of its own. This is level 0, to follow the convention used by
///   [`NodeIndex`]. This means that if the level count begins at the top of the tree, it should
///   include the root level. By way of example, a tree with 8 leaves has _4_ levels in this
///   counting.
/// - You cannot have a zero number of levels, which is enforced by construction.
/// - The number of levels cannot exceed [`MAX_NUM_SUBTREE_LEVELS`]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubtreeLevels {
    value: u8,
}

impl SubtreeLevels {
    /// Constructs a new number of levels, or returns [`None`] if the type invariants are violated.
    pub fn new(value: u8) -> Option<SubtreeLevels> {
        if value == 0 || value > MAX_NUM_SUBTREE_LEVELS {
            return None;
        }
        Some(SubtreeLevels { value })
    }

    /// Constructs a number of levels, trusting that the provided `value` maintains the invariants
    /// of the type.
    ///
    /// Using this type if the invariants have been violated may result in undefined computational
    /// behaviour, up to and including crashes at runtime and data corruption. To that end, in debug
    /// builds it will panic if the invariants are violated.
    pub fn new_unchecked(value: u8) -> SubtreeLevels {
        assert!(
            value <= MAX_NUM_SUBTREE_LEVELS && value > 0,
            "{value} is not a valid number of subtree levels"
        );
        SubtreeLevels { value }
    }

    /// Gets the number of non-root levels in the subtree.
    pub fn non_root_levels(&self) -> u8 {
        self.value - 1
    }
}

impl From<SubtreeLevels> for u8 {
    fn from(value: SubtreeLevels) -> Self {
        value.value
    }
}

impl From<SubtreeLevels> for u32 {
    fn from(value: SubtreeLevels) -> Self {
        value.value as u32
    }
}

impl From<SubtreeLevels> for u64 {
    fn from(value: SubtreeLevels) -> Self {
        value.value as u64
    }
}

impl Display for SubtreeLevels {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.value)
    }
}

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts the provided `ix` into a linear index for use in the prefix, based on the addressing
/// scheme set out in the [`LinearIndex`] documentation.
#[must_use]
pub fn node_index_to_linear(ix: NodeIndex) -> LinearIndex {
    // The NodeIndex is a pair of (depth, index_from_left) where the root is (0, 0).
    (1 << ix.depth() as u64) + ix.value()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn node_index_to_lin() {
        // Check the edge-cases to start with, being both the minimum and maximum supported number
        // of levels.
        assert_eq!(node_index_to_linear(NodeIndex::new_unchecked(0, 0)), 1);
        assert_eq!(
            node_index_to_linear(NodeIndex::new_unchecked(62, 2u64.pow(62) - 1)),
            2u64.pow(63) - 1
        );

        // Then we can try some random ones.
        assert_eq!(node_index_to_linear(NodeIndex::new_unchecked(7, 3)), 2u64.pow(7) + 3);
        assert_eq!(
            node_index_to_linear(NodeIndex::new_unchecked(21, 2u64.pow(12))),
            2u64.pow(21) + 2u64.pow(12)
        );
    }
}
