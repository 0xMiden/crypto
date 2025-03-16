use core::{
    fmt::{Binary, Display},
    ops::{BitAnd, BitOr, BitXor, BitXorAssign, ShlAssign},
};

use crate::Felt;

/// A compact representation of trees (or peaks) in Merkle Mountain Range (MMR)
/// 
/// Each active bit of the stored number represents a disjoint tree with number of leaves
/// equal to the bit position.
/// 
/// Examples:
/// - Forest(0) is a forest with no trees.
/// - Forest(0b01) is a forest with a single node (the smallest tree possible)
/// - Forest(0b10) is a forest with a single binary tree with 2 leaves (3 modes)
/// - Forest(0b11) is a forest with two trees: one with a single node, and one with 3 nodes
/// - Forest(0b1010) is a forest with two trees: one with 8 leaves (15 nodes),
///     one with 2 leaves (3 nodes)
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Forest(usize);

impl Forest {
    /// Creates an empty forest (no trees)
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates a forest with n leaves
    pub const fn with_leaves(n: usize) -> Self {
        Self(n)
    }

    /// Returns true if there are no trees in the forest.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns a forest with a capacity for exactly one more leaf
    /// Some smaller trees might be merged together.
    pub fn with_new_leaf(&mut self) -> Forest {
        Forest(self.0 + 1)
    }

    /// Returns a count of leaves in the entire underlying Forest (MMR).
    pub fn num_leaves(self) -> usize {
        self.0
    }

    /// Return the total number of nodes of a given forest
    ///
    /// Panics:
    ///
    /// This will panic if the forest has size greater than `usize::MAX / 2`
    pub const fn num_nodes(self) -> usize {
        self.0 * 2 - self.num_trees() as usize
    }

    /// Return the total number of trees of a given forest (the number of active bits)
    pub const fn num_trees(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns the height (bit position) of the largest tree in the forest
    pub fn largest_tree_height(self) -> usize {
        self.0.ilog2() as usize
    }

    /// Returns a forest with only the largest tree present.
    ///
    /// Panics:
    ///
    /// This will panic if the forest is empty.
    pub fn largest_tree(self) -> Forest {
        Forest::with_leaves(1 << self.largest_tree_height())
    }

    /// Returns a forest with only the largest tree preset.
    /// If forest cannot be empty, use `largest_tree` for performance.
    pub fn largest_tree_checked(self) -> Forest {
        if self.0 > 0 {
            self.largest_tree()
        } else {
            Forest::empty()
        }
    }

    /// Returns the height (bit position) of the smallest tree in the forest
    pub fn smallest_tree_height(self) -> usize {
        self.0.trailing_zeros() as usize
    }

    /// Returns a forest with only the smallest tree present.
    ///
    /// Panics:
    ///
    /// This will panic if the forest is empty.
    pub fn smallest_tree(self) -> Forest {
        Forest::with_leaves(1 << self.smallest_tree_height())
    }

    /// Returns a forest with only the smallest tree preset.
    /// If forest cannot be empty, use `smallest_tree` for performance.
    pub fn smallest_tree_checked(self) -> Forest {
        if self.0 > 0 {
            self.smallest_tree()
        } else {
            Forest::empty()
        }
    }

    /// Keeps only trees larger than the reference tree.
    pub fn trees_larger_than(self, base: u32) -> Forest {
        self & high_bitmask(base + 1)
    }

    /// Creates a new forest with all possible trees smaller than
    /// the smallest tree in this forest.
    pub fn all_smaller_trees(self) -> Forest {
        debug_assert!(self.0.count_ones() == 1);
        Forest::with_leaves(self.0 - 1)
    }

    /// Returns true if the forest containts a single-node tree
    pub fn has_odd_leaf(self) -> bool {
        self.0 & 1 != 0
    }

    /// Add a single-node tree if not already present in the forest.
    pub fn odd_leaf_added(self) -> Forest {
        Forest::with_leaves(self.0 | 1)
    }

    /// Remove the single-node tree if present in the forest.
    pub fn odd_leaf_removed(self) -> Forest {
        Forest::with_leaves(self.0 & (usize::MAX << 1))
    }

    /// Given a 0-indexed leaf position in the current forest, return the tree number responsible
    /// for the position.
    ///
    /// Note:
    /// The result is a tree position `p`, it has the following interpretations. $p+1$ is the depth
    /// of the tree. Because the root element is not part of the proof, $p$ is the length of the
    /// authentication path. $2^p$ is equal to the number of leaves in this particular tree. and
    /// $2^(p+1)-1$ corresponds to size of the tree.
    pub fn leaf_to_corresponding_tree(self, pos: usize) -> Option<u32> {
        let forest = self.0;

        if pos >= forest {
            None
        } else {
            // - each bit in the forest is a unique tree and the bit position its power-of-two size
            // - each tree owns a consecutive range of positions equal to its size from
            //   left-to-right
            // - this means the first tree owns from `0` up to the `2^k_0` first positions, where
            //   `k_0` is the highest true bit position, the second tree from `2^k_0 + 1` up to
            //   `2^k_1` where `k_1` is the second highest bit, so on.
            // - this means the highest bits work as a category marker, and the position is owned by
            //   the first tree which doesn't share a high bit with the position
            let before = forest & pos;
            let after = forest ^ before;
            let tree = after.ilog2();

            Some(tree)
        }
    }

    /// Given a 0-indexed leaf position in the current forest, return the 0-indexed leaf position
    /// in the tree to which the leaf belongs.
    pub fn leaf_relative_position(self, pos: usize) -> Option<usize> {
        let tree = self.leaf_to_corresponding_tree(pos)?;
        let forest_before = self & high_bitmask(tree + 1);
        Some(pos - forest_before.0)
    }

}

impl Display for Forest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Binary for Forest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:b}", self.0)
    }
}

impl BitAnd<Forest> for Forest {
    type Output = Forest;

    fn bitand(self, rhs: Forest) -> Self::Output {
        Forest::with_leaves(self.0 & rhs.0)
    }
}

impl BitOr<Forest> for Forest {
    type Output = Forest;

    fn bitor(self, rhs: Forest) -> Self::Output {
        Forest::with_leaves(self.0 | rhs.0)
    }
}

impl BitXor<Forest> for Forest {
    type Output = Forest;

    fn bitxor(self, rhs: Forest) -> Self::Output {
        Forest::with_leaves(self.0 ^ rhs.0)
    }
}

impl BitXorAssign<Forest> for Forest {
    fn bitxor_assign(&mut self, rhs: Forest) {
        self.0 ^= rhs.0;
    }
}

impl ShlAssign<usize> for Forest {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}

impl From<Felt> for Forest {
    fn from(value: Felt) -> Self {
        Self::with_leaves(value.as_int() as usize)
    }
}

impl Into<Felt> for Forest {
    fn into(self) -> Felt {
        Felt::new(self.0 as u64)
    }
}


/// Return a bitmask for the bits including and above the given position.
pub(crate) const fn high_bitmask(bit: u32) -> Forest {
    if bit > usize::BITS - 1 {
        Forest::empty()
    } else {
        Forest::with_leaves(usize::MAX << bit)
    }
}
