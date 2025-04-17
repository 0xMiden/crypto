use core::{
    fmt::{Binary, Display},
    ops::{BitAnd, BitOr, BitXor, BitXorAssign, ShlAssign},
};

use crate::Felt;

/// A compact representation of trees (or peaks) in Merkle Mountain Range (MMR).
///
/// Each active bit of the stored number represents a disjoint tree with number of leaves
/// equal to the bit position.
///
/// Examples:
/// - `MountainRange(0)` is a forest with no trees.
/// - `MountainRange(0b01)` is a forest with a single leaf/node (the smallest tree possible).
/// - `MountainRange(0b10)` is a forest with a single binary tree with 2 leaves (3 nodes).
/// - `MountainRange(0b11)` is a forest with two trees: one with 1 leaf (1 node), and one with 2
///   leaves (3
/// nodes).
/// - `MountainRange(0b1010)` is a forest with two trees: one with 8 leaves (15 nodes), one with 2
///   leaves (3 nodes).
/// - `MountainRange(0b1000)` is a forest with one tree, which has 8 leaves (15 nodes).
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MountainRange(usize);

impl MountainRange {
    /// Creates an empty mountain range (no trees).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates a mountain range with `n` leaves.
    pub const fn new(num_leaves: usize) -> Self {
        Self(num_leaves)
    }

    /// Returns true if there are no trees in the mountain range.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns a mountain range with a capacity for exactly one more leaf.
    ///
    /// Some smaller trees might be merged together.
    pub fn increment(&mut self) {
        self.0 += 1;
    }

    /// Returns a count of leaves in the entire underlying Mountain Range (MMR).
    pub fn num_leaves(self) -> usize {
        self.0
    }

    /// Return the total number of nodes of a given mountain range.
    ///
    /// # Panics
    ///
    /// This will panic if the mountain range has size greater than `usize::MAX / 2`.
    pub const fn num_nodes(self) -> usize {
        self.0 * 2 - self.num_trees()
    }

    /// Return the total number of trees of a given mountain range (the number of active bits).
    pub const fn num_trees(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns the height (bit position) of the largest tree in the mountain range.
    pub fn largest_tree_height(self) -> usize {
        // ilog2 is computed with leading zeros, which itself is computed with the intrinsic ctlz.
        // [Rust 1.67.0] x86 uses the `bsr` instruction. AArch64 uses the `clz` instruction.
        self.0.ilog2() as usize
    }

    /// Returns a mountain range with only the largest tree present.
    ///
    /// # Panics
    ///
    /// This will panic if the mountain range is empty.
    pub fn largest_tree_unchecked(self) -> MountainRange {
        MountainRange::new(1 << self.largest_tree_height())
    }

    /// Returns a mountain range with only the largest tree present.
    ///
    /// If mountain range cannot be empty, use `largest_tree` for better performance.
    pub fn largest_tree(self) -> MountainRange {
        if self.0 > 0 {
            self.largest_tree()
        } else {
            MountainRange::empty()
        }
    }

    /// Returns the height (bit position) of the smallest tree in the mountain range.
    pub fn smallest_tree_height(self) -> usize {
        // Trailing_zeros is computed with the intrinsic cttz. [Rust 1.67.0] x86 uses the `bsf`
        // instruction. AArch64 uses the `rbit clz` instructions.
        self.0.trailing_zeros() as usize
    }

    /// Returns a mountain range with only the smallest tree present.
    ///
    /// # Panics
    ///
    /// This will panic if the mountain range is empty.
    pub fn smallest_tree_unchecked(self) -> MountainRange {
        MountainRange::new(1 << self.smallest_tree_height())
    }

    /// Returns a mountain range with only the smallest tree present.
    ///
    /// If mountain range cannot be empty, use `smallest_tree` for performance.
    pub fn smallest_tree(self) -> MountainRange {
        if self.0 > 0 {
            self.smallest_tree_unchecked()
        } else {
            MountainRange::empty()
        }
    }

    /// Keeps only trees larger than the reference tree.
    ///
    /// For example, if we start with the bit pattern `0b0101_0110`, and keep only the trees larger
    /// than tree index 1, that targets this bit:
    /// ```text
    /// MountainRange(0b0101_0110).trees_larger_than(1)
    ///                        ^
    /// Becomes:      0b0101_0100
    ///                        ^
    /// ```
    /// And keeps only trees *after* that bit, meaning that the tree at `tree_idx` is also removed,
    /// resulting in `0b0101_0100`.
    ///
    /// ```
    /// # use miden_crypto::merkle::MountainRange;
    /// let range = MountainRange::new(0b0101_0110);
    /// assert_eq!(range.trees_larger_than(1), MountainRange::new(0b0101_0100));
    /// ```
    pub fn trees_larger_than(self, tree_idx: u32) -> MountainRange {
        self & high_bitmask(tree_idx + 1)
    }

    /// Creates a new mountain range with all possible trees smaller than the smallest tree in this
    /// mountain range.
    pub fn all_smaller_trees(self) -> MountainRange {
        debug_assert!(self.0.count_ones() == 1);
        MountainRange::new(self.0 - 1)
    }

    /// Returns true if the mountain range contains a single-node tree.
    pub fn has_single_leaf_tree(self) -> bool {
        self.0 & 1 != 0
    }

    /// Add a single-node tree if not already present in the mountain range.
    pub fn single_leaf_tree_added(self) -> MountainRange {
        MountainRange::new(self.0 | 1)
    }

    /// Remove the single-node tree if present in the mountain range.
    pub fn single_leaf_tree_removed(self) -> MountainRange {
        MountainRange::new(self.0 & (usize::MAX << 1))
    }

    /// Returns a new mountain range that does not have the trees that `other` has.
    pub fn without_trees(self, other: MountainRange) -> Self {
        self ^ other
    }

    /// Given a leaf index in the current mountain range, return the tree number responsible for the leaf.
    ///
    /// Note:
    /// The result is a tree position `p`, it has the following interpretations:
    /// - `p+1` is the depth of the tree.
    /// - Because the root element is not part of the proof, `p` is the length of the
    /// authentication path.
    /// - `2^p` is equal to the number of leaves in this particular tree.
    /// - And `2^(p+1)-1` corresponds to the size of the tree.
    /// 
    /// For example, given a mountain range with 6 leaves whose forest is `0b110`:
    /// ```
    ///       __ peak 2 __
    ///      /            \
    ///    ____          ____         _ peak 1 _
    ///   /    \        /    \       /          \
    ///  0      1      2      3     4            5
    /// ```
    ///
    /// Leaf indices `0..=3` are in the tree at index 2 and leaf indices `4..=5` are in the tree at index 1.
    pub fn leaf_to_corresponding_tree(self, leaf_idx: usize) -> Option<u32> {
        let forest = self.0;

        if leaf_idx >= forest {
            None
        } else {
            // - each bit in the mountain range is a unique tree and the bit position is its
            //   power-of-two size
            // - each tree is associated to a consecutive range of positions equal to its size from
            //   left-to-right
            // - this means the first tree owns from `0` up to the `2^k_0` first positions, where
            //   `k_0` is the highest set bit position, the second tree from `2^k_0 + 1` up to
            //   `2^k_1` where `k_1` is the second highest bit, so on.
            // - this means the highest bits work as a category marker, and the position is owned by
            //   the first tree which doesn't share a high bit with the position
            let before = forest & leaf_idx;
            let after = forest ^ before;
            let tree_idx = after.ilog2();

            Some(tree_idx)
        }
    }

    /// Given a leaf index in the current mountain range, return the lead index in the tree to which the leaf belongs..
    pub(super) fn leaf_relative_position(self, leaf_idx: usize) -> Option<usize> {
        let tree_idx = self.leaf_to_corresponding_tree(leaf_idx)?;
        let forest_before = self & high_bitmask(tree_idx + 1);
        Some(leaf_idx - forest_before.0)
    }
}

impl Display for MountainRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Binary for MountainRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:b}", self.0)
    }
}

impl BitAnd<MountainRange> for MountainRange {
    type Output = MountainRange;

    fn bitand(self, rhs: MountainRange) -> Self::Output {
        MountainRange::new(self.0 & rhs.0)
    }
}

impl BitOr<MountainRange> for MountainRange {
    type Output = MountainRange;

    fn bitor(self, rhs: MountainRange) -> Self::Output {
        MountainRange::new(self.0 | rhs.0)
    }
}

impl BitXor<MountainRange> for MountainRange {
    type Output = MountainRange;

    fn bitxor(self, rhs: MountainRange) -> Self::Output {
        MountainRange::new(self.0 ^ rhs.0)
    }
}

impl BitXorAssign<MountainRange> for MountainRange {
    fn bitxor_assign(&mut self, rhs: MountainRange) {
        self.0 ^= rhs.0;
    }
}

impl ShlAssign<usize> for MountainRange {
    fn shl_assign(&mut self, rhs: usize) {
        self.0 <<= rhs;
    }
}

impl From<Felt> for MountainRange {
    fn from(value: Felt) -> Self {
        Self::new(value.as_int() as usize)
    }
}

impl From<MountainRange> for Felt {
    fn from(value: MountainRange) -> Felt {
        Felt::new(value.0 as u64)
    }
}

/// Return a bitmask for the bits including and above the given position.
pub(crate) const fn high_bitmask(bit: u32) -> MountainRange {
    if bit > usize::BITS - 1 {
        MountainRange::empty()
    } else {
        MountainRange::new(usize::MAX << bit)
    }
}
