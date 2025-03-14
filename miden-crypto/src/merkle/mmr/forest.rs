use core::{fmt::Display, ops::{BitAnd, BitOr, BitXor, BitXorAssign, ShlAssign}};

// TODO: make the field private
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Forest(pub usize);

// TODO: add Felt conversion methods
impl Forest {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn add_leaf(&mut self) {
        self.0 += 1;
    }

    /// Returns a count of leaves in the underlying MMR.
    pub fn num_leaves(self) -> usize {
        self.0
    }
    
    // TODO: make it usize for consistency
    pub fn num_trees(self) -> usize {
        self.0.count_ones() as usize
    }

    pub fn highest_tree(self) -> Forest {
        Forest(1 << self.0.ilog2())
    }

    pub fn smallest_tree_height(self) -> usize {
        self.0.trailing_zeros() as usize
    }

    pub fn smallest_tree(self) -> Forest {
        Forest(1 << self.0.trailing_zeros())
    }

    pub fn smallest_tree_checked(self) -> Forest {
        let result = 1usize.checked_shl(self.0.trailing_zeros()).unwrap_or(0);
        Forest(result)
    }

    // TODO: this is not great if it's not a single tree
    // maybe debug_assert is sufficient
    pub fn all_smaller_trees(self) -> Forest {
        debug_assert!(self.0.count_ones() == 1);
        Forest(self.0 - 1)
    }

    pub fn has_odd_leaf(self) -> bool {
        self.0 & 1 != 0
    }

    pub fn odd_leaf_removed(self) -> Forest {
        Forest(self.0 & (usize::MAX << 1))
    }

    /// Return the total number of nodes of a given forest
    ///
    /// Panics:
    ///
    /// This will panic if the forest has size greater than `usize::MAX / 2`
    pub fn num_nodes(self) -> usize {
        self.0 * 2 - self.num_trees() as usize
    }

    pub fn contains_tree(self, tree: usize) -> bool {
        (self.0 & tree) != 0
    }

    /// Given a 0-indexed leaf position and the current forest, return the tree number responsible for
    /// the position.
    ///
    /// Note:
    /// The result is a tree position `p`, it has the following interpretations. $p+1$ is the depth of
    /// the tree. Because the root element is not part of the proof, $p$ is the length of the
    /// authentication path. $2^p$ is equal to the number of leaves in this particular tree. and
    /// $2^(p+1)-1$ corresponds to size of the tree.
    pub fn leaf_to_corresponding_tree(self, pos: usize) -> Option<u32> {
        let forest = self.0;

        if pos >= forest {
            None
        } else {
            // - each bit in the forest is a unique tree and the bit position its power-of-two size
            // - each tree owns a consecutive range of positions equal to its size from left-to-right
            // - this means the first tree owns from `0` up to the `2^k_0` first positions, where `k_0`
            //   is the highest true bit position, the second tree from `2^k_0 + 1` up to `2^k_1` where
            //   `k_1` is the second highest bit, so on.
            // - this means the highest bits work as a category marker, and the position is owned        by the
            //   first tree which doesn't share a high bit with the position
            let before = forest & pos;
            let after = forest ^ before;
            let tree = after.ilog2();

            Some(tree)
        }
    }
    
    pub fn leaf_relative_position(self, pos: usize) -> Option<usize> {
        let tree = self.leaf_to_corresponding_tree(pos)?;
        let forest_before = self & high_bitmask(tree + 1);
        Some(pos - forest_before.0)
    }

    pub fn leaf_coordinates(self, pos: usize) -> Option<(u32, usize)> {
        let tree = self.leaf_to_corresponding_tree(pos)?;
        let forest_before = self & high_bitmask(tree + 1);
        //let tree_offset = forest_before.num_nodes();
        let leaf_offset = pos - forest_before.0;
        Some((tree, leaf_offset))
    }

    pub fn diff(self, other: Forest) -> Forest {
        Forest(self.0 ^ other.0)
    }

    pub fn intersect(self, other: Forest) -> Forest {
        Forest(self.0 & other.0)
    }

    pub fn union(self, other: Forest) -> Forest {
        Forest(self.0 | other.0)
    }

    pub fn max_tree_height(self) -> usize {
        1 << self.0.ilog2()
    }
}

impl Display for Forest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BitAnd<Forest> for Forest {
    type Output = Forest;

    fn bitand(self, rhs: Forest) -> Self::Output {
        Forest(self.0 & rhs.0)
    }
}

impl BitOr<Forest> for Forest {
    type Output = Forest;

    fn bitor(self, rhs: Forest) -> Self::Output {
        Forest(self.0 | rhs.0)
    }
}

impl BitXor<Forest> for Forest {
    type Output = Forest;

    fn bitxor(self, rhs: Forest) -> Self::Output {
        Forest(self.0 ^ rhs.0)
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

/// Return a bitmask for the bits including and above the given position.
pub(crate) const fn high_bitmask(bit: u32) -> Forest {
    if bit > usize::BITS - 1 {
        Forest::empty()
    } else {
        Forest(usize::MAX << bit)
    }
}

pub fn nodes_in_tree(tree: u64) -> u64 {
    2 * tree - 1
}
