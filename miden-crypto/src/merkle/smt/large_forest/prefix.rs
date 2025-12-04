//! This module contains the type definition and methods for working with the in-memory prefix of
//! each tree in the forest.

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

use super::error::prefix::{PrefixError, Result};
use crate::{
    EMPTY_WORD, Word,
    hash::rpo::Rpo256,
    merkle::{
        NodeIndex,
        smt::{
            SubtreeLevels,
            large_forest::utils::{LinearIndex, node_index_to_linear},
        },
    },
};

// IN MEMORY PREFIX
// ================================================================================================

/// An in-memory tree prefix that stores all nodes for the first `n` levels of the tree in
/// fully-materialised form.
#[allow(dead_code)] // Temporary
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryPrefix {
    /// The number of levels that are stored in the prefix, including the root level.
    ///
    /// See the documentation on [`SubtreeLevels`] for more information on the invariants of
    /// this type.
    pub num_levels: SubtreeLevels,

    /// The storage for the nodes in the in-memory prefix, which will have space to store
    /// `2.pow(num_levels)` nodes without reallocation.
    ///
    /// It is laid out such that it is indexable by [`LinearIndex`].
    pub nodes: Vec<Word>,
}

#[allow(dead_code)] // Temporary
impl InMemoryPrefix {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new prefix with the specified `num_levels`, using `leaf_data` as the starting
    /// value for the leaves of the prefix, and with `expected_root` as the expected root.
    ///
    /// # Errors
    ///
    /// - [`PrefixError::InvalidRestoration`] if the provided `leaf_data` does not build into a tree
    ///   with a root matching `expected_root`.
    /// - [`PrefixError::WrongLeafCount`] if the provided `leaf_data` contains the wrong number of
    ///   leaves for a prefix with `num_levels` levels.
    pub fn new(
        num_levels: SubtreeLevels,
        leaf_data: Vec<Word>,
        expected_root: Word,
    ) -> Result<Self> {
        // We also want to fail if we are provided with the wrong number of leaves to build the
        // in-memory tree.
        let expected_leaf_count = 2u64.pow(num_levels.non_root_levels() as u32);
        let actual_leaf_count = leaf_data.len() as u64;
        if actual_leaf_count != expected_leaf_count {
            return Err(PrefixError::WrongLeafCount(actual_leaf_count, expected_leaf_count));
        }

        // Finally, we want to fail if the computed root is incorrect.
        let nodes = Self::build_tree_from_leaves(num_levels, leaf_data);
        if nodes[1] != expected_root {
            return Err(PrefixError::InvalidRestoration(expected_root, nodes[1]));
        }

        // If all of that succeeds we have a valid in-memory tree.
        Ok(Self { num_levels, nodes })
    }

    /// Builds a fully-materialized merkle tree from the provided `leaves`.
    fn build_tree_from_leaves(num_levels: SubtreeLevels, leaves: Vec<Word>) -> Vec<Word> {
        // We start by allocating our output buffer to the correct size with default values of
        // EMPTY_WORD.
        let num_cells = 2usize.pow(num_levels.into());
        let mut nodes = vec![EMPTY_WORD; num_cells];

        // We then copy our leaves into the last `leaves.len()` cells of the buffer.
        let first_ix = num_cells - leaves.len();
        nodes[first_ix..num_cells].copy_from_slice(&leaves);

        // We then do a bottom-up computation of the tree nodes. This has the potential to be
        // parallelized, but whether the effort is worthwhile depends on the usual number of levels
        // kept in the prefix, especially as multiple prefixes will be built in parallel by the
        // forest.
        for i in (1..first_ix).rev() {
            let left = nodes[2 * i];
            let right = nodes[2 * i + 1];
            nodes[i] = Rpo256::merge(&[left, right]);
        }

        nodes
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Gets a reference to the item at the provided index.
    ///
    /// # Errors
    ///
    /// - [`PrefixError::IndexOutOfBounds`] if the provided `index` is not in bounds for the
    ///   container.
    pub fn get(&self, index: LinearIndex) -> Result<&Word> {
        self.fail_if_oob(index)?;
        Ok(&self.nodes[index as usize])
    }

    /// Gets a mutable reference to the item at the provided index.
    ///
    /// Note that mutating the value at the reference will not update the rest of the in-memory
    /// prefix, as this is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// - [`PrefixError::IndexOutOfBounds`] if the provided `index` is not in bounds for the
    ///   container.
    pub fn get_mut(&mut self, index: LinearIndex) -> Result<&mut Word> {
        self.fail_if_oob(index)?;
        Ok(&mut self.nodes[index as usize])
    }

    /// Gets a reference to the item at the provided index.
    ///
    /// # Errors
    ///
    /// - [`PrefixError::IndexOutOfBounds`] if the provided `index` is not in bounds for the
    ///   container.
    pub fn get_node_index(&self, index: NodeIndex) -> Result<&Word> {
        let lin_ix = node_index_to_linear(index);
        self.fail_if_oob(lin_ix)?;
        Ok(&self.nodes[lin_ix as usize])
    }

    /// Gets a mutable reference to the item at the provided index.
    ///
    /// Note that mutating the value at the reference will not update the rest of the in-memory
    /// prefix, as this is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// - [`PrefixError::IndexOutOfBounds`] if the provided `index` is not in bounds for the
    ///   container.
    pub fn get_mut_node_index(&mut self, index: NodeIndex) -> Result<&mut Word> {
        let lin_ix = node_index_to_linear(index);
        self.fail_if_oob(lin_ix)?;
        Ok(&mut self.nodes[lin_ix as usize])
    }

    // INTERNAL UTILITIES
    // ============================================================================================

    /// Fails with [`PrefixError::IndexOutOfBounds`] if the provided `index` is out of bounds in the
    /// prefix.
    fn fail_if_oob(&self, index: LinearIndex) -> Result<()> {
        if index == 0 || index >= 2u64.pow(self.num_levels.into()) {
            return Err(PrefixError::IndexOutOfBounds(index, self.num_levels.into()));
        }
        Ok(())
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Index<LinearIndex> for InMemoryPrefix {
    type Output = Word;

    /// # Panics
    ///
    /// Will panic if the index is out of bounds, or if the index is zero in debug builds.
    fn index(&self, index: LinearIndex) -> &Self::Output {
        assert!(index > 0, "The prefix uses one-based indexing");
        &self.nodes[index as usize]
    }
}

/// Note that mutating the value at the reference will not update the rest of the in-memory
/// prefix, as this is the caller's responsibility.
impl IndexMut<LinearIndex> for InMemoryPrefix {
    /// # Panics
    ///
    /// Will panic if the index is out of bounds, or if the index is zero in debug builds.
    fn index_mut(&mut self, index: LinearIndex) -> &mut Self::Output {
        assert!(index > 0, "The prefix uses one-based indexing");
        &mut self.nodes[index as usize]
    }
}

impl Index<NodeIndex> for InMemoryPrefix {
    type Output = Word;

    /// # Panics
    ///
    /// Will panic if the index is out of bounds for the prefix.
    fn index(&self, index: NodeIndex) -> &Self::Output {
        let lin_ix = node_index_to_linear(index);
        &self.nodes[lin_ix as usize]
    }
}

/// Note that mutating the value at the reference will not update the rest of the in-memory
/// prefix, as this is the caller's responsibility.
impl IndexMut<NodeIndex> for InMemoryPrefix {
    /// # Panics
    ///
    /// Will panic if the index is out of bounds for the prefix.
    fn index_mut(&mut self, index: NodeIndex) -> &mut Self::Output {
        let lin_ix = node_index_to_linear(index);
        &mut self.nodes[lin_ix as usize]
    }
}

// TESTS
// ================================================================================================

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::Result;
    use crate::{
        EMPTY_WORD,
        hash::rpo::Rpo256,
        merkle::{
            NodeIndex,
            smt::{
                SubtreeLevels,
                large_forest::{error::prefix::PrefixError, prefix::InMemoryPrefix},
            },
        },
        rand::test_utils::rand_value,
    };

    #[test]
    fn new_wrong_leaf_count() {
        // It should also error out when passing the wrong number of leaves for the specified number
        // of levels.
        assert_eq!(
            InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), vec![EMPTY_WORD; 6], rand_value()),
            Err(PrefixError::WrongLeafCount(6, 8))
        )
    }

    #[test]
    fn new_wrong_root() {
        // Let's start by setting up some test data.
        let leaves = vec![
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
        ];
        let expected_root = Rpo256::merge(&[
            Rpo256::merge(&[
                Rpo256::merge(&[leaves[0], leaves[1]]),
                Rpo256::merge(&[leaves[2], leaves[3]]),
            ]),
            Rpo256::merge(&[
                Rpo256::merge(&[leaves[4], leaves[5]]),
                Rpo256::merge(&[leaves[6], leaves[7]]),
            ]),
        ]);

        // It should error out if the wrong root is provided.
        assert_eq!(
            InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, EMPTY_WORD),
            Err(PrefixError::InvalidRestoration(EMPTY_WORD, expected_root))
        )
    }

    #[test]
    fn new_successful() {
        // Let's start by setting up some test data.
        let leaves = vec![
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
            rand_value(),
        ];
        let expected_root = Rpo256::merge(&[
            Rpo256::merge(&[
                Rpo256::merge(&[leaves[0], leaves[1]]),
                Rpo256::merge(&[leaves[2], leaves[3]]),
            ]),
            Rpo256::merge(&[
                Rpo256::merge(&[leaves[4], leaves[5]]),
                Rpo256::merge(&[leaves[6], leaves[7]]),
            ]),
        ]);

        // When we construct it with the correct arguments we should succeed.
        assert!(
            InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, expected_root).is_ok()
        );
    }

    #[test]
    fn get_by_linear_index() -> Result<()> {
        // Let's start by setting up some test data.
        let leaf_1 = rand_value();
        let leaf_2 = rand_value();
        let leaf_3 = rand_value();
        let leaf_4 = rand_value();
        let leaf_5 = rand_value();
        let leaf_6 = rand_value();
        let leaf_7 = rand_value();
        let leaf_8 = rand_value();
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_4, leaf_5, leaf_6, leaf_7, leaf_8];

        let node_2_0 = Rpo256::merge(&[leaf_1, leaf_2]);
        let node_2_1 = Rpo256::merge(&[leaf_3, leaf_4]);
        let node_2_2 = Rpo256::merge(&[leaf_5, leaf_6]);
        let node_2_3 = Rpo256::merge(&[leaf_7, leaf_8]);
        let node_1_0 = Rpo256::merge(&[node_2_0, node_2_1]);
        let node_1_1 = Rpo256::merge(&[node_2_2, node_2_3]);
        let root = Rpo256::merge(&[node_1_0, node_1_1]);

        let mut prefix = InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, root)?;

        // We can now query by the linear index to retrieve values and check they are correct. We
        // start with `0` which is a special value and shouldn't be accessed, and 16 which is one
        // past the end.
        assert_eq!(prefix.get(0), Err(PrefixError::IndexOutOfBounds(0, 4)));
        assert_eq!(prefix.get(16), Err(PrefixError::IndexOutOfBounds(16, 4)));

        // But if we query at valid indices we should get the right results back.
        assert_eq!(prefix.get(1)?, &root);
        assert_eq!(prefix.get(15)?, &leaf_8);
        assert_eq!(prefix.get(7)?, &node_2_3);
        assert_eq!(prefix.get(8)?, &leaf_1);

        // We can also get a mutable reference, allowing us to mutate.
        let new_value = rand_value();
        *prefix.get_mut(15)? = new_value;
        assert_eq!(prefix.get(15)?, &new_value);

        // But doing this will leave other values unchanged.
        assert_eq!(prefix.get(1)?, &root);

        Ok(())
    }

    #[test]
    fn get_by_node_index() -> Result<()> {
        // Let's start by setting up some test data.
        let leaf_1 = rand_value();
        let leaf_2 = rand_value();
        let leaf_3 = rand_value();
        let leaf_4 = rand_value();
        let leaf_5 = rand_value();
        let leaf_6 = rand_value();
        let leaf_7 = rand_value();
        let leaf_8 = rand_value();
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_4, leaf_5, leaf_6, leaf_7, leaf_8];

        let node_2_0 = Rpo256::merge(&[leaf_1, leaf_2]);
        let node_2_1 = Rpo256::merge(&[leaf_3, leaf_4]);
        let node_2_2 = Rpo256::merge(&[leaf_5, leaf_6]);
        let node_2_3 = Rpo256::merge(&[leaf_7, leaf_8]);
        let node_1_0 = Rpo256::merge(&[node_2_0, node_2_1]);
        let node_1_1 = Rpo256::merge(&[node_2_2, node_2_3]);
        let root = Rpo256::merge(&[node_1_0, node_1_1]);

        let mut prefix = InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, root)?;

        // We can now query by the linear index to retrieve values and check they are correct. We
        // start with (4, 0), which is out of bounds.
        assert_eq!(
            prefix.get_node_index(NodeIndex::new_unchecked(4, 0)),
            Err(PrefixError::IndexOutOfBounds(16, 4))
        );

        // But if we query at valid indices we should get the right results back.
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(0, 0))?, &root);
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(3, 7))?, &leaf_8);
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(2, 3))?, &node_2_3);
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(3, 0))?, &leaf_1);

        // We can also get a mutable reference, allowing us to mutate.
        let new_value = rand_value();
        *prefix.get_mut_node_index(NodeIndex::new_unchecked(3, 7))? = new_value;
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(3, 7))?, &new_value);

        // But doing this will leave other values unchanged.
        assert_eq!(prefix.get_node_index(NodeIndex::new_unchecked(0, 0))?, &root);

        Ok(())
    }

    #[test]
    fn index_by_linear_index() -> Result<()> {
        // Let's start by setting up some test data.
        let leaf_1 = rand_value();
        let leaf_2 = rand_value();
        let leaf_3 = rand_value();
        let leaf_4 = rand_value();
        let leaf_5 = rand_value();
        let leaf_6 = rand_value();
        let leaf_7 = rand_value();
        let leaf_8 = rand_value();
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_4, leaf_5, leaf_6, leaf_7, leaf_8];

        let node_2_0 = Rpo256::merge(&[leaf_1, leaf_2]);
        let node_2_1 = Rpo256::merge(&[leaf_3, leaf_4]);
        let node_2_2 = Rpo256::merge(&[leaf_5, leaf_6]);
        let node_2_3 = Rpo256::merge(&[leaf_7, leaf_8]);
        let node_1_0 = Rpo256::merge(&[node_2_0, node_2_1]);
        let node_1_1 = Rpo256::merge(&[node_2_2, node_2_3]);
        let root = Rpo256::merge(&[node_1_0, node_1_1]);

        let mut prefix = InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, root)?;

        // We can now query by the linear index to retrieve values and check they are correct.
        assert_eq!(prefix[1], root);
        assert_eq!(prefix[15], leaf_8);
        assert_eq!(prefix[7], node_2_3);
        assert_eq!(prefix[8], leaf_1);

        // We can also get a mutable reference, allowing us to mutate.
        let new_value = rand_value();
        prefix[15] = new_value;
        assert_eq!(prefix[15], new_value);

        // But doing this will leave other values unchanged.
        assert_eq!(prefix[1], root);

        Ok(())
    }

    #[test]
    fn index_by_node_index() -> Result<()> {
        // Let's start by setting up some test data.
        let leaf_1 = rand_value();
        let leaf_2 = rand_value();
        let leaf_3 = rand_value();
        let leaf_4 = rand_value();
        let leaf_5 = rand_value();
        let leaf_6 = rand_value();
        let leaf_7 = rand_value();
        let leaf_8 = rand_value();
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_4, leaf_5, leaf_6, leaf_7, leaf_8];

        let node_2_0 = Rpo256::merge(&[leaf_1, leaf_2]);
        let node_2_1 = Rpo256::merge(&[leaf_3, leaf_4]);
        let node_2_2 = Rpo256::merge(&[leaf_5, leaf_6]);
        let node_2_3 = Rpo256::merge(&[leaf_7, leaf_8]);
        let node_1_0 = Rpo256::merge(&[node_2_0, node_2_1]);
        let node_1_1 = Rpo256::merge(&[node_2_2, node_2_3]);
        let root = Rpo256::merge(&[node_1_0, node_1_1]);

        let mut prefix = InMemoryPrefix::new(SubtreeLevels::new_unchecked(4), leaves, root)?;

        // We can now query by the linear index to retrieve values and check they are correct.
        assert_eq!(prefix[NodeIndex::new_unchecked(0, 0)], root);
        assert_eq!(prefix[NodeIndex::new_unchecked(3, 7)], leaf_8);
        assert_eq!(prefix[NodeIndex::new_unchecked(2, 3)], node_2_3);
        assert_eq!(prefix[NodeIndex::new_unchecked(3, 0)], leaf_1);

        // We can also get a mutable reference, allowing us to mutate.
        let new_value = rand_value();
        prefix[NodeIndex::new_unchecked(3, 7)] = new_value;
        assert_eq!(prefix[NodeIndex::new_unchecked(3, 7)], new_value);

        // But doing this will leave other values unchanged.
        assert_eq!(prefix[NodeIndex::new_unchecked(0, 0)], root);

        Ok(())
    }
}
