use core::{
    fmt::{Binary, Display},
    ops::{BitAnd, BitOr, BitXor, BitXorAssign},
};

use super::InOrderIndex;
use crate::Felt;

/// A compact representation of trees in a forest. Used in the Merkle forest (MMR).
///
/// Each active bit of the stored number represents a disjoint tree with number of leaves
/// equal to the bit position.
///
/// The forest value has the following interpretations:
/// - its value is the number of leaves in the forest
/// - the version number (MMR is append only so the number of leaves always increases)
/// - bit count corresponds to the number of trees (trees) in the forest
/// - each true bit position determines the depth of a tree in the forest
///
/// Examples:
/// - `Forest(0)` is a forest with no trees.
/// - `Forest(0b01)` is a forest with a single leaf/node (the smallest tree possible).
/// - `Forest(0b10)` is a forest with a single binary tree with 2 leaves (3 nodes).
/// - `Forest(0b11)` is a forest with two trees: one with 1 leaf (1 node), and one with 2 leaves (3
///   nodes).
/// - `Forest(0b1010)` is a forest with two trees: one with 8 leaves (15 nodes), one with 2 leaves
///   (3 nodes).
/// - `Forest(0b1000)` is a forest with one tree, which has 8 leaves (15 nodes).
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Forest(usize);

impl Forest {
    /// Creates an empty forest (no trees).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates a forest with `num_leaves` leaves.
    pub const fn new(num_leaves: usize) -> Self {
        Self(num_leaves)
    }

    /// Creates a forest with a given height.
    ///
    /// This is equivalent to `Forest::new(1 << height)`.
    ///
    /// # Panics
    ///
    /// This will panic if `height` is greater than `usize::BITS - 1`.
    pub const fn with_height(height: usize) -> Self {
        assert!(height < usize::BITS as usize);
        Self::new(1 << height)
    }

    /// Returns true if there are no trees in the forest.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Adds exactly one more leaf to the capacity of this forest.
    ///
    /// Some smaller trees might be merged together.
    pub fn append_leaf(&mut self) {
        self.0 += 1;
    }

    /// Returns a count of leaves in the entire underlying forest (MMR).
    pub fn num_leaves(self) -> usize {
        self.0
    }

    /// Return the total number of nodes of a given forest.
    ///
    /// # Panics
    ///
    /// This will panic if the forest has size greater than `usize::MAX / 2 + 1`.
    pub const fn num_nodes(self) -> usize {
        assert!(self.0 <= usize::MAX / 2 + 1);
        if self.0 <= usize::MAX / 2 {
            self.0 * 2 - self.num_trees()
        } else {
            // If `self.0 > usize::MAX / 2` then we need 128-bit math to double it.
            let (inner, num_trees) = (self.0 as u128, self.num_trees() as u128);
            (inner * 2 - num_trees) as usize
        }
    }

    /// Return the total number of trees of a given forest (the number of active bits).
    pub const fn num_trees(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns the height (bit position) of the largest tree in the forest.
    ///
    /// # Panics
    ///
    /// This will panic if the forest is empty.
    pub fn largest_tree_height_unchecked(self) -> usize {
        // ilog2 is computed with leading zeros, which itself is computed with the intrinsic ctlz.
        // [Rust 1.67.0] x86 uses the `bsr` instruction. AArch64 uses the `clz` instruction.
        self.0.ilog2() as usize
    }

    /// Returns the height (bit position) of the largest tree in the forest.
    ///
    /// If the forest cannot be empty, use [`largest_tree_height_unchecked`] for performance.
    ///
    /// [`largest_tree_height_unchecked`]: Self::largest_tree_height_unchecked
    pub fn largest_tree_height(self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        Some(self.largest_tree_height_unchecked())
    }

    /// Returns a forest with only the largest tree present.
    ///
    /// # Panics
    ///
    /// This will panic if the forest is empty.
    pub fn largest_tree_unchecked(self) -> Self {
        Self::with_height(self.largest_tree_height_unchecked())
    }

    /// Returns a forest with only the largest tree present.
    ///
    /// If forest cannot be empty, use `largest_tree` for better performance.
    pub fn largest_tree(self) -> Self {
        if self.is_empty() {
            return Self::empty();
        }

        self.largest_tree_unchecked()
    }

    /// Returns the height (bit position) of the smallest tree in the forest.
    ///
    /// # Panics
    ///
    /// This will panic if the forest is empty.
    pub fn smallest_tree_height_unchecked(self) -> usize {
        // Trailing_zeros is computed with the intrinsic cttz. [Rust 1.67.0] x86 uses the `bsf`
        // instruction. AArch64 uses the `rbit clz` instructions.
        self.0.trailing_zeros() as usize
    }

    /// Returns the height (bit position) of the smallest tree in the forest.
    ///
    /// If the forest cannot be empty, use [`smallest_tree_height_unchecked`] for better
    /// performance.
    ///
    /// [`smallest_tree_height_unchecked`]: Self::smallest_tree_height_unchecked
    pub fn smallest_tree_height(self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        Some(self.smallest_tree_height_unchecked())
    }

    /// Returns a forest with only the smallest tree present.
    ///
    /// # Panics
    ///
    /// This will panic if the forest is empty.
    pub fn smallest_tree_unchecked(self) -> Self {
        Self::with_height(self.smallest_tree_height_unchecked())
    }

    /// Returns a forest with only the smallest tree present.
    ///
    /// If forest cannot be empty, use `smallest_tree` for performance.
    pub fn smallest_tree(self) -> Self {
        if self.is_empty() {
            return Self::empty();
        }
        self.smallest_tree_unchecked()
    }

    /// Keeps only trees larger than the reference tree.
    ///
    /// For example, if we start with the bit pattern `0b0101_0110`, and keep only the trees larger
    /// than tree index 1, that targets this bit:
    /// ```text
    /// Forest(0b0101_0110).trees_larger_than(1)
    ///                        ^
    /// Becomes:      0b0101_0100
    ///                        ^
    /// ```
    /// And keeps only trees *after* that bit, meaning that the tree at `tree_idx` is also removed,
    /// resulting in `0b0101_0100`.
    ///
    /// ```
    /// # use miden_crypto::merkle::Forest;
    /// let range = Forest::new(0b0101_0110);
    /// assert_eq!(range.trees_larger_than(1), Forest::new(0b0101_0100));
    /// ```
    pub fn trees_larger_than(self, tree_idx: u32) -> Self {
        self & high_bitmask(tree_idx + 1)
    }

    /// Creates a new forest with all possible trees smaller than the smallest tree in this
    /// forest.
    ///
    /// This forest must have exactly one tree.
    ///
    /// # Panics
    /// With debug assertions enabled, this function panics if this forest does not have
    /// exactly one tree.
    ///
    /// For a non-panicking version of this function, see [`Forest::all_smaller_trees()`].
    pub fn all_smaller_trees_unchecked(self) -> Self {
        debug_assert_eq!(self.num_trees(), 1);
        Self::new(self.0 - 1)
    }

    /// Creates a new forest with all possible trees smaller than the smallest tree in this
    /// forest, or returns `None` if this forest has more or less than one tree.
    ///
    /// If the forest cannot have more or less than one tree, use
    /// [`Forest::all_smaller_trees_unchecked()`] for performance.
    pub fn all_smaller_trees(self) -> Option<Forest> {
        if self.num_trees() != 1 {
            return None;
        }
        Some(self.all_smaller_trees_unchecked())
    }

    /// Returns a forest with exactly one tree, one size (depth) larger than the current one.
    pub fn next_larger_tree(self) -> Self {
        debug_assert_eq!(self.num_trees(), 1);
        Forest(self.0 << 1)
    }

    /// Returns true if the forest contains a single-node tree.
    pub fn has_single_leaf_tree(self) -> bool {
        self.0 & 1 != 0
    }

    /// Add a single-node tree if not already present in the forest.
    pub fn with_single_leaf(self) -> Self {
        Self::new(self.0 | 1)
    }

    /// Remove the single-node tree if present in the forest.
    pub fn without_single_leaf(self) -> Self {
        Self::new(self.0 & (usize::MAX - 1))
    }

    /// Returns a new forest that does not have the trees that `other` has.
    pub fn without_trees(self, other: Forest) -> Self {
        self ^ other
    }

    /// Returns index of the forest tree for a specified leaf index.
    pub fn tree_index(&self, leaf_idx: usize) -> usize {
        let root = self
            .leaf_to_corresponding_tree(leaf_idx)
            .expect("position must be part of the forest");
        let smaller_tree_mask = Self::new(2_usize.pow(root) - 1);
        let num_smaller_trees = (*self & smaller_tree_mask).num_trees();
        self.num_trees() - num_smaller_trees - 1
    }

    /// Returns the smallest tree's root element as an [InOrderIndex].
    ///
    /// This function takes the smallest tree in this forest, "pretends" that it is a subtree of a
    /// fully balanced binary tree, and returns the the in-order index of that balanced tree's root
    /// node.
    pub fn root_in_order_index(&self) -> InOrderIndex {
        // Count total size of all trees in the forest.
        let nodes = self.num_nodes();

        // Add the count for the parent nodes that separate each tree. These are allocated but
        // currently empty, and correspond to the nodes that will be used once the trees are merged.
        let open_trees = self.num_trees() - 1;

        // Remove the leaf-count of the rightmost subtree. The target tree root index comes before
        // the subtree, for the in-order tree walk.
        let right_subtree_count = self.smallest_tree_unchecked().num_leaves() - 1;

        let idx = nodes + open_trees - right_subtree_count;

        InOrderIndex::new(idx.try_into().unwrap())
    }

    /// Returns the in-order index of the rightmost element (the smallest tree).
    pub fn rightmost_in_order_index(&self) -> InOrderIndex {
        // Count total size of all trees in the forest.
        let nodes = self.num_nodes();

        // Add the count for the parent nodes that separate each tree. These are allocated but
        // currently empty, and correspond to the nodes that will be used once the trees are merged.
        let open_trees = self.num_trees() - 1;

        let idx = nodes + open_trees;

        InOrderIndex::new(idx.try_into().unwrap())
    }

    /// Given a leaf index in the current forest, return the tree number responsible for the
    /// leaf.
    ///
    /// Note:
    /// The result is a tree position `p`, it has the following interpretations:
    /// - `p+1` is the depth of the tree.
    /// - Because the root element is not part of the proof, `p` is the length of the authentication
    ///   path.
    /// - `2^p` is equal to the number of leaves in this particular tree.
    /// - And `2^(p+1)-1` corresponds to the size of the tree.
    ///
    /// For example, given a forest with 6 leaves whose forest is `0b110`:
    /// ```text
    ///       __ tree 2 __
    ///      /            \
    ///    ____          ____         _ tree 1 _
    ///   /    \        /    \       /          \
    ///  0      1      2      3     4            5
    /// ```
    ///
    /// Leaf indices `0..=3` are in the tree at index 2 and leaf indices `4..=5` are in the tree at
    /// index 1.
    pub fn leaf_to_corresponding_tree(self, leaf_idx: usize) -> Option<u32> {
        let forest = self.0;

        if leaf_idx >= forest {
            None
        } else {
            // - each bit in the forest is a unique tree and the bit position is its power-of-two
            //   size
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

    /// Given a leaf index in the current forest, return the leaf index in the tree to which
    /// the leaf belongs.
    pub(super) fn leaf_relative_position(self, leaf_idx: usize) -> Option<usize> {
        let tree_idx = self.leaf_to_corresponding_tree(leaf_idx)?;
        let forest_before = self & high_bitmask(tree_idx + 1);
        Some(leaf_idx - forest_before.0)
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
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::new(self.0 & rhs.0)
    }
}

impl BitOr<Forest> for Forest {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::new(self.0 | rhs.0)
    }
}

impl BitXor<Forest> for Forest {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::new(self.0 ^ rhs.0)
    }
}

impl BitXorAssign<Forest> for Forest {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl From<Felt> for Forest {
    fn from(value: Felt) -> Self {
        Self::new(value.as_int() as usize)
    }
}

impl From<Forest> for Felt {
    fn from(value: Forest) -> Self {
        Felt::new(value.0 as u64)
    }
}

/// Return a bitmask for the bits including and above the given position.
pub(crate) const fn high_bitmask(bit: u32) -> Forest {
    if bit > usize::BITS - 1 {
        Forest::empty()
    } else {
        Forest::new(usize::MAX << bit)
    }
}

// TREE SIZE ITERATOR
// ================================================================================================

/// Iterate over the trees within this `Forest`, from smallest to largest.
///
/// Each item is a "sub-forest", containing only one tree.
pub struct TreeSizeIterator {
    inner: Forest,
}

impl TreeSizeIterator {
    pub fn new(value: Forest) -> TreeSizeIterator {
        TreeSizeIterator { inner: value }
    }
}

impl Iterator for TreeSizeIterator {
    type Item = Forest;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.inner.smallest_tree();

        if tree.is_empty() {
            None
        } else {
            self.inner = self.inner.without_trees(tree);
            Some(tree)
        }
    }
}

impl DoubleEndedIterator for TreeSizeIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.inner.largest_tree();

        if tree.is_empty() {
            None
        } else {
            self.inner = self.inner.without_trees(tree);
            Some(tree)
        }
    }
}
