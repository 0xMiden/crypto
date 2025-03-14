//! A fully materialized Merkle mountain range (MMR).
//!
//! A MMR is a forest structure, i.e. it is an ordered set of disjoint rooted trees. The trees are
//! ordered by size, from the most to least number of leaves. Every tree is a perfect binary tree,
//! meaning a tree has all its leaves at the same depth, and every inner node has a branch-factor
//! of 2 with both children set.
//!
//! Additionally the structure only supports adding leaves to the right-most tree, the one with the
//! least number of leaves. The structure preserves the invariant that each tree has different
//! depths, i.e. as part of adding a new element to the forest the trees with same depth are
//! merged, creating a new tree with depth d+1, this process is continued until the property is
//! reestablished.
use alloc::vec::Vec;

use super::{
    super::{InnerNodeInfo, MerklePath},
    MmrDelta, MmrError, MmrPeaks, MmrProof, Rpo256, Word,
    bit::TrueBitPositionIterator,
    forest::{Forest, high_bitmask},
    nodes_in_forest,
};

// MMR
// ===============================================================================================

/// A fully materialized Merkle Mountain Range, with every tree in the forest and all their
/// elements.
///
/// Since this is a full representation of the MMR, elements are never removed and the MMR will
/// grow roughly `O(2n)` in number of leaf elements.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Mmr {
    /// Refer to the `forest` method documentation for details of the semantics of this value.
    pub(super) forest: Forest,

    /// Contains every element of the forest.
    ///
    /// The trees are in postorder sequential representation. This representation allows for all
    /// the elements of every tree in the forest to be stored in the same sequential buffer. It
    /// also means new elements can be added to the forest, and merging of trees is very cheap with
    /// no need to copy elements.
    pub(super) nodes: Vec<Word>,
}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmr {
    // CONSTRUCTORS
    // ============================================================================================

    /// Constructor for an empty `Mmr`.
    pub fn new() -> Mmr {
        Mmr {
            forest: Forest::default(),
            nodes: Vec::new(),
        }
    }

    // ACCESSORS
    // ============================================================================================

    /// Returns the MMR forest representation.
    ///
    /// The forest value has the following interpretations:
    /// - its value is the number of elements in the forest
    /// - bit count corresponds to the number of trees in the forest
    /// - each true bit position determines the depth of a tree in the forest
    pub const fn forest(&self) -> usize {
        self.forest.0
    }

    // FUNCTIONALITY
    // ============================================================================================

    /// Returns an [MmrProof] for the leaf at the specified position.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if the specified leaf position is out of bounds for this MMR.
    pub fn open(&self, pos: usize) -> Result<MmrProof, MmrError> {
        self.open_at(pos, self.forest)
    }

    /// Returns an [MmrProof] for the leaf at the specified position using the state of the MMR
    /// at the specified `forest`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified leaf position is out of bounds for this MMR.
    /// - The specified `forest` value is not valid for this MMR.
    pub fn open_at(&self, pos: usize, forest: Forest) -> Result<MmrProof, MmrError> {
        // find the target tree responsible for the MMR position
        let tree_bit =
            forest.leaf_to_corresponding_tree(pos).ok_or(MmrError::PositionNotFound(pos))?;

        // isolate the trees before the target
        let forest_before = forest & high_bitmask(tree_bit + 1);
        let index_offset = forest_before.num_nodes();

        // update the value position from global to the target tree
        let relative_pos = pos - forest_before.num_leaves();

        // collect the path and the final index of the target value
        let (_, path) = self.collect_merkle_path_and_value(tree_bit, relative_pos, index_offset);

        Ok(MmrProof {
            forest,
            position: pos,
            merkle_path: MerklePath::new(path),
        })
    }

    /// Returns the leaf value at position `pos`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    pub fn get(&self, pos: usize) -> Result<Word, MmrError> {
        // find the target tree responsible for the MMR position
        let tree_bit = self
            .forest
            .leaf_to_corresponding_tree(pos)
            .ok_or(MmrError::PositionNotFound(pos))?;

        // isolate the trees before the target
        let forest_before = self.forest & high_bitmask(tree_bit + 1);
        let index_offset = forest_before.num_nodes();

        // update the value position from global to the target tree
        let relative_pos = pos - forest_before.num_leaves();

        // collect the path and the final index of the target value
        let (value, _) = self.collect_merkle_path_and_value(tree_bit, relative_pos, index_offset);

        Ok(value)
    }

    /// Adds a new element to the MMR.
    pub fn add(&mut self, el: Word) {
        // Note: every node is also a tree of size 1, adding an element to the forest creates a new
        // rooted-tree of size 1. This may temporarily break the invariant that every tree in the
        // forest has different sizes, the loop below will eagerly merge trees of same size and
        // restore the invariant.
        self.nodes.push(el);

        let mut left_offset = self.nodes.len().saturating_sub(2);
        let mut right = el;
        let mut left_tree = 1;
        while !(self.forest & Forest(left_tree)).is_empty() {
            right = Rpo256::merge(&[self.nodes[left_offset], right]);
            self.nodes.push(right);

            left_offset = left_offset.saturating_sub(Forest(left_tree).num_nodes());
            left_tree <<= 1;
        }

        self.forest.0 += 1;
    }

    /// Returns the current peaks of the MMR.
    pub fn peaks(&self) -> MmrPeaks {
        self.peaks_at(self.forest).expect("failed to get peaks at current forest")
    }

    /// Returns the peaks of the MMR at the state specified by `forest`.
    ///
    /// # Errors
    /// Returns an error if the specified `forest` value is not valid for this MMR.
    pub fn peaks_at(&self, forest: Forest) -> Result<MmrPeaks, MmrError> {
        if forest > self.forest {
            return Err(MmrError::InvalidPeaks(format!(
                "requested forest {forest} exceeds current forest {}",
                self.forest
            )));
        }

        let peaks: Vec<Word> = TrueBitPositionIterator::new(forest)
            .rev()
            .map(|tree| tree.num_nodes())
            .scan(0, |offset, el| {
                *offset += el;
                Some(*offset)
            })
            .map(|offset| self.nodes[offset - 1])
            .collect();

        // Safety: the invariant is maintained by the [Mmr]
        let peaks = MmrPeaks::new(forest.0, peaks).unwrap();

        Ok(peaks)
    }

    /// Compute the required update to `original_forest`.
    ///
    /// The result is a packed sequence of the authentication elements required to update the trees
    /// that have been merged together, followed by the new peaks of the [Mmr].
    pub fn get_delta(&self, from_forest: usize, to_forest: usize) -> Result<MmrDelta, MmrError> {
        let from_forest = Forest(from_forest);
        let to_forest = Forest(to_forest);

        if to_forest > self.forest || from_forest > to_forest {
            return Err(MmrError::InvalidPeaks(format!(
                "to_forest {to_forest} exceeds the current forest {} or from_forest {from_forest} exceeds to_forest",
                self.forest
            )));
        }

        if from_forest == to_forest {
            return Ok(MmrDelta { forest: to_forest.0, data: Vec::new() });
        }

        let mut result = Vec::new();

        // Find the largest tree in this [Mmr] which is new to `from_forest`.
        let candidate_trees = to_forest ^ from_forest; // xor remains the best description of the op
        let mut new_high = candidate_trees.highest_tree(); // TODO: largest tree (in number of leaves)

        // Collect authentication nodes used for tree merges
        // ----------------------------------------------------------------------------------------

        // Find the trees from `from_forest` that have been merged into `new_high`.
        let mut merges = from_forest & new_high.all_smaller_trees();

        // Find the peaks that are common to `from_forest` and this [Mmr]
        let common_trees = from_forest ^ merges; // alternatively: from_forest & !(new_high - 1)

        if !merges.is_empty() {
            // Skip the smallest trees unknown to `from_forest`.
            let mut target = merges.smallest_tree();

            // Collect siblings required to computed the merged tree's peak
            while target < new_high {
                // Computes the offset to the smallest know peak
                // - common_trees: peaks unchanged in the current update, target comes after these.
                // - merges: peaks that have not been merged so far, target comes after these.
                // - target: tree from which to load the sibling. On the first iteration this is a
                //   value known by the partial mmr, on subsequent iterations this value is to be
                //   computed from the known peaks and provided authentication nodes.
                let known = (common_trees | merges | target).num_nodes();
                let sibling = target.num_nodes();
                result.push(self.nodes[known + sibling - 1]);

                // Update the target and account for tree merges
                target <<= 1;
                while !(merges & target).is_empty() {
                    target <<= 1;
                }
                // Remove the merges done so far
                merges ^= merges & target.all_smaller_trees();
            }
        } else {
            // The new high tree may not be the result of any merges, if it is smaller than all the
            // trees of `from_forest`.
            new_high = Forest::empty();
        }

        // Collect the new [Mmr] peaks
        // ----------------------------------------------------------------------------------------

        let mut new_peaks = to_forest ^ common_trees ^ new_high;
        let old_peaks = to_forest ^ new_peaks;
        let mut offset = old_peaks.num_nodes();
        while !new_peaks.is_empty() {
            let target = new_peaks.highest_tree();
            offset += target.num_nodes();
            result.push(self.nodes[offset - 1]);
            new_peaks ^= target;
        }

        Ok(MmrDelta { forest: to_forest.0, data: result })
    }

    /// An iterator over inner nodes in the MMR. The order of iteration is unspecified.
    pub fn inner_nodes(&self) -> MmrNodes {
        MmrNodes {
            mmr: self,
            forest: 0,
            last_right: 0,
            index: 0,
        }
    }

    // UTILITIES
    // ============================================================================================

    /// Internal function used to collect the Merkle path of a value.
    ///
    /// The arguments are relative to the target tree. To compute the opening of the second leaf
    /// for a tree with depth 2 in the forest `0b110`:
    ///
    /// - `tree_bit`: Depth of the target tree, e.g. 2 for the smallest tree.
    /// - `relative_pos`: 0-indexed leaf position in the target tree, e.g. 1 for the second leaf.
    /// - `index_offset`: Node count prior to the target tree, e.g. 7 for the tree of depth 3.
    fn collect_merkle_path_and_value(
        &self,
        tree_bit: u32,
        relative_pos: usize,
        index_offset: usize,
    ) -> (Word, Vec<Word>) {
        // see documentation of `leaf_to_corresponding_tree` for details
        let tree_depth = (tree_bit + 1) as usize;
        let mut path = Vec::with_capacity(tree_depth);

        // The tree walk below goes from the root to the leaf, compute the root index to start
        let mut forest_target = 1usize << tree_bit;
        let mut index = nodes_in_forest(forest_target) - 1;

        // Loop until the leaf is reached
        while forest_target > 1 {
            // Update the depth of the tree to correspond to a subtree
            forest_target >>= 1;

            // compute the indices of the right and left subtrees based on the post-order
            let right_offset = index - 1;
            let left_offset = right_offset - nodes_in_forest(forest_target);

            let left_or_right = relative_pos & forest_target;
            let sibling = if left_or_right != 0 {
                // going down the right subtree, the right child becomes the new root
                index = right_offset;
                // and the left child is the authentication
                self.nodes[index_offset + left_offset]
            } else {
                index = left_offset;
                self.nodes[index_offset + right_offset]
            };

            path.push(sibling);
        }

        debug_assert!(path.len() == tree_depth - 1);

        // the rest of the codebase has the elements going from leaf to root, adjust it here for
        // easy of use/consistency sake
        path.reverse();

        let value = self.nodes[index_offset + index];
        (value, path)
    }
}

// CONVERSIONS
// ================================================================================================

impl<T> From<T> for Mmr
where
    T: IntoIterator<Item = Word>,
{
    fn from(values: T) -> Self {
        let mut mmr = Mmr::new();
        for v in values {
            mmr.add(v)
        }
        mmr
    }
}

// ITERATOR
// ===============================================================================================

/// Yields inner nodes of the [Mmr].
pub struct MmrNodes<'a> {
    /// [Mmr] being yielded, when its `forest` value is matched, the iterations is finished.
    mmr: &'a Mmr,
    /// Keeps track of the left nodes yielded so far waiting for a right pair, this matches the
    /// semantics of the [Mmr]'s forest attribute, since that too works as a buffer of left nodes
    /// waiting for a pair to be hashed together.
    forest: usize,
    /// Keeps track of the last right node yielded, after this value is set, the next iteration
    /// will be its parent with its corresponding left node that has been yield already.
    last_right: usize,
    /// The current index in the `nodes` vector.
    index: usize,
}

impl Iterator for MmrNodes<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        debug_assert!(self.last_right.count_ones() <= 1, "last_right tracks zero or one element");

        // only parent nodes are emitted, remove the single node tree from the forest
        let target = self.mmr.forest.odd_leaf_removed();

        if self.forest < target.0 {
            if self.last_right == 0 {
                // yield the left leaf
                debug_assert!(self.last_right == 0, "left must be before right");
                self.forest |= 1;
                self.index += 1;

                // yield the right leaf
                debug_assert!((self.forest & 1) == 1, "right must be after left");
                self.last_right |= 1;
                self.index += 1;
            };

            debug_assert!(
                self.forest & self.last_right != 0,
                "parent requires both a left and right",
            );

            // compute the number of nodes in the right tree, this is the offset to the
            // previous left parent
            let right_nodes = nodes_in_forest(self.last_right);
            // the next parent position is one above the position of the pair
            let parent = self.last_right << 1;

            // the left node has been paired and the current parent yielded, removed it from the
            // forest
            self.forest ^= self.last_right;
            if self.forest & parent == 0 {
                // this iteration yielded the left parent node
                debug_assert!(self.forest & 1 == 0, "next iteration yields a left leaf");
                self.last_right = 0;
                self.forest ^= parent;
            } else {
                // the left node of the parent level has been yielded already, this iteration
                // was the right parent. Next iteration yields their parent.
                self.last_right = parent;
            }

            // yields a parent
            let value = self.mmr.nodes[self.index];
            let right = self.mmr.nodes[self.index - 1];
            let left = self.mmr.nodes[self.index - 1 - right_nodes];
            self.index += 1;
            let node = InnerNodeInfo { value, left, right };

            Some(node)
        } else {
            None
        }
    }
}
