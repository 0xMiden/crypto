use alloc::{borrow::Cow, vec::Vec};
use core::{
    iter::{self, FusedIterator},
    num::NonZero,
};

use winter_utils::{Deserializable, DeserializationError, Serializable};

use super::{
    EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, NodeIndex, SMT_MAX_DEPTH, ValuePath,
    Word,
};
use crate::hash::rpo::Rpo256;

/// A different representation of [`MerklePath`] designed for memory efficiency for Merkle paths
/// with empty nodes.
///
/// Empty nodes in the path are stored only as their position, represented with a bitmask. A
/// maximum of 64 nodes (`SMT_MAX_DEPTH`) can be stored (empty and non-empty). The more nodes in a
/// path are empty, the less memory this struct will use. This type calculates empty nodes on-demand
/// when iterated through, converted to a [MerklePath], or an empty node is retrieved with
/// [`SparseMerklePath::at_depth()`], which will incur overhead.
///
/// NOTE: This type assumes that Merkle paths always span from the root of the tree to a leaf.
/// Partial paths are not supported.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SparseMerklePath {
    /// A bitmask representing empty nodes. The set bit corresponds to the depth of an empty node.
    /// The least significant bit (bit 0) describes depth 1 node (root's children).
    /// The `bit index + 1` is equal to node's depth.
    empty_nodes_mask: u64,
    /// The non-empty nodes, stored in depth-order, but not contiguous across depth.
    nodes: Vec<Word>,
}

impl SparseMerklePath {
    /// Constructs a sparse Merkle path from an iterator over Merkle nodes that also knows its
    /// exact size (such as iterators created with [Vec::into_iter]). The iterator must be in order
    /// of deepest to shallowest.
    ///
    /// Knowing the size is necessary to calculate the depth of the tree, which is needed to detect
    /// which nodes are empty nodes.
    ///
    /// # Errors
    /// Returns [MerkleError::DepthTooBig] if `tree_depth` is greater than [SMT_MAX_DEPTH].
    pub fn from_sized_iter<I>(iterator: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<IntoIter: ExactSizeIterator, Item = Word>,
    {
        let iterator = iterator.into_iter();
        let tree_depth = iterator.len() as u8;

        if tree_depth > SMT_MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }

        let mut empty_nodes_mask: u64 = 0;
        let mut nodes: Vec<Word> = Default::default();

        for (depth, node) in iter::zip(path_depth_iter(tree_depth), iterator) {
            let &equivalent_empty_node = EmptySubtreeRoots::entry(tree_depth, depth.get());
            let is_empty = node == equivalent_empty_node;
            let node = if is_empty { None } else { Some(node) };

            match node {
                Some(node) => nodes.push(node),
                None => empty_nodes_mask |= Self::bitmask_for_depth(depth),
            }
        }

        Ok(SparseMerklePath { nodes, empty_nodes_mask })
    }

    /// Returns the total depth of this path, i.e., the number of nodes this path represents.
    pub fn depth(&self) -> u8 {
        (self.nodes.len() + self.empty_nodes_mask.count_ones() as usize) as u8
    }

    /// Get a specific node in this path at a given depth.
    ///
    /// The `depth` parameter is defined in terms of `self.depth()`. Merkle paths conventionally do
    /// not include the root, so the shallowest depth is `1`, and the deepest depth is
    /// `self.depth()`.
    ///
    /// # Errors
    /// Returns [MerkleError::DepthTooBig] if `node_depth` is greater than the total depth of this
    /// path.
    pub fn at_depth(&self, node_depth: NonZero<u8>) -> Result<Word, MerkleError> {
        if node_depth.get() > self.depth() {
            return Err(MerkleError::DepthTooBig(node_depth.get().into()));
        }

        let node = if let Some(nonempty_index) = self.get_nonempty_index(node_depth) {
            self.nodes[nonempty_index]
        } else {
            *EmptySubtreeRoots::entry(self.depth(), node_depth.get())
        };

        Ok(node)
    }

    // PROVIDERS
    // ============================================================================================

    /// Constructs a borrowing iterator over the nodes in this path.
    /// Starts from the leaf and iterates toward the root (excluding the root).
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Word> {
        self.into_iter()
    }

    /// Computes the Merkle root for this opening.
    pub fn compute_root(&self, index: u64, node_to_prove: Word) -> Result<Word, MerkleError> {
        let mut index = NodeIndex::new(self.depth(), index)?;
        let root = self.iter().fold(node_to_prove, |node, sibling| {
            // Compute the node and move to the next iteration.
            let children = index.build_node(node, sibling);
            index.move_up();
            Rpo256::merge(&children)
        });

        Ok(root)
    }

    /// Verifies the Merkle opening proof towards the provided root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - provided node index is invalid.
    /// - root calculated during the verification differs from the provided one.
    pub fn verify(&self, index: u64, node: Word, &expected_root: &Word) -> Result<(), MerkleError> {
        let computed_root = self.compute_root(index, node)?;
        if computed_root != expected_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root,
                actual_root: computed_root,
            });
        }

        Ok(())
    }

    /// Given the node this path opens to, return an iterator of all the nodes that are known via
    /// this path.
    ///
    /// Each item in the iterator is an [InnerNodeInfo], containing the hash of a node as `.value`,
    /// and its two children as `.left` and `.right`. The very first item in that iterator will be
    /// the parent of `node_to_prove` as stored in this [SparseMerklePath].
    ///
    /// From there, the iterator will continue to yield every further parent and both of its
    /// children, up to and including the root node.
    ///
    /// If `node_to_prove` is not the node this path is an opening to, or `index` is not the
    /// correct index for that node, the returned nodes will be meaningless.
    ///
    /// # Errors
    /// Returns an error if the specified index is not valid for this path.
    pub fn authenticated_nodes(
        &self,
        index: u64,
        node_to_prove: Word,
    ) -> Result<InnerNodeIterator, MerkleError> {
        let index = NodeIndex::new(self.depth(), index)?;
        Ok(InnerNodeIterator { path: self, index, value: node_to_prove })
    }

    // PRIVATE HELPERS
    // ============================================================================================

    const fn bitmask_for_depth(node_depth: NonZero<u8>) -> u64 {
        // - 1 because paths do not include the root.
        1 << (node_depth.get() - 1)
    }

    const fn is_depth_empty(&self, node_depth: NonZero<u8>) -> bool {
        (self.empty_nodes_mask & Self::bitmask_for_depth(node_depth)) != 0
    }

    /// Index of the non-empty node in the `self.nodes` vector. If the specified depth is
    /// empty, None is returned.
    fn get_nonempty_index(&self, node_depth: NonZero<u8>) -> Option<usize> {
        if self.is_depth_empty(node_depth) {
            return None;
        }

        let bit_index = node_depth.get() - 1;
        let without_shallower = self.empty_nodes_mask >> bit_index;
        let empty_deeper = without_shallower.count_ones() as usize;
        // The vec index we would use if we didn't have any empty nodes to account for...
        let normal_index = (self.depth() - node_depth.get()) as usize;
        // subtracted by the number of empty nodes that are deeper than us.
        Some(normal_index - empty_deeper)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SparseMerklePath {
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.depth());
        target.write_u64(self.empty_nodes_mask);
        target.write_many(&self.nodes);
    }
}

impl Deserializable for SparseMerklePath {
    fn read_from<R: winter_utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let depth = source.read_u8()?;
        if depth > SMT_MAX_DEPTH {
            return Err(DeserializationError::InvalidValue(format!(
                "SparseMerklePath max depth exceeded ({depth} > {SMT_MAX_DEPTH})",
            )));
        }
        let empty_nodes_mask = source.read_u64()?;
        let empty_nodes_count = empty_nodes_mask.count_ones();
        if empty_nodes_count > depth as u32 {
            return Err(DeserializationError::InvalidValue(format!(
                "SparseMerklePath has more empty nodes ({empty_nodes_count}) than its full length ({depth})",
            )));
        }
        let count = depth as u32 - empty_nodes_count;
        let nodes = source.read_many::<Word>(count as usize)?;
        Ok(Self { empty_nodes_mask, nodes })
    }
}

// CONVERSIONS
// ================================================================================================

impl From<SparseMerklePath> for MerklePath {
    fn from(sparse_path: SparseMerklePath) -> Self {
        MerklePath::from_iter(sparse_path)
    }
}

impl TryFrom<MerklePath> for SparseMerklePath {
    type Error = MerkleError;

    /// # Errors
    ///
    /// This conversion returns [MerkleError::DepthTooBig] if the path length is greater than
    /// [`SMT_MAX_DEPTH`].
    fn try_from(path: MerklePath) -> Result<Self, MerkleError> {
        SparseMerklePath::from_sized_iter(path)
    }
}

impl From<SparseMerklePath> for Vec<Word> {
    fn from(path: SparseMerklePath) -> Self {
        Vec::from_iter(path)
    }
}

// ITERATORS
// ================================================================================================

/// Iterator for [`SparseMerklePath`]. Starts from the leaf and iterates toward the root (excluding
/// the root).
pub struct SparseMerklePathIter<'p> {
    /// The "inner" value we're iterating over.
    path: Cow<'p, SparseMerklePath>,

    /// The depth a `next()` call will get. `next_depth == 0` indicates that the iterator has been
    /// exhausted.
    next_depth: u8,
}

impl Iterator for SparseMerklePathIter<'_> {
    type Item = Word;

    fn next(&mut self) -> Option<Word> {
        let this_depth = self.next_depth;
        // Paths don't include the root, so if `this_depth` is 0 then we keep returning `None`.
        let this_depth = NonZero::new(this_depth)?;
        self.next_depth = this_depth.get() - 1;

        // `this_depth` is only ever decreasing, so it can't ever exceed `self.path.depth()`.
        let node = self
            .path
            .at_depth(this_depth)
            .expect("current depth should never exceed the path depth");
        Some(node)
    }

    // SparseMerkleIter always knows its exact size.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = ExactSizeIterator::len(self);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SparseMerklePathIter<'_> {
    fn len(&self) -> usize {
        self.next_depth as usize
    }
}

impl FusedIterator for SparseMerklePathIter<'_> {}

// TODO: impl DoubleEndedIterator.

impl IntoIterator for SparseMerklePath {
    type IntoIter = SparseMerklePathIter<'static>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> SparseMerklePathIter<'static> {
        let tree_depth = self.depth();
        SparseMerklePathIter {
            path: Cow::Owned(self),
            next_depth: tree_depth,
        }
    }
}

impl<'p> IntoIterator for &'p SparseMerklePath {
    type Item = <SparseMerklePathIter<'p> as Iterator>::Item;
    type IntoIter = SparseMerklePathIter<'p>;

    fn into_iter(self) -> SparseMerklePathIter<'p> {
        let tree_depth = self.depth();
        SparseMerklePathIter {
            path: Cow::Borrowed(self),
            next_depth: tree_depth,
        }
    }
}

/// An iterator over nodes known by a [SparseMerklePath]. See
/// [`SparseMerklePath::authenticated_nodes()`].
pub struct InnerNodeIterator<'p> {
    path: &'p SparseMerklePath,
    index: NodeIndex,
    value: Word,
}

impl Iterator for InnerNodeIterator<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index.is_root() {
            return None;
        }

        let index_depth = NonZero::new(self.index.depth()).expect("non-root depth cannot be 0");
        let path_node = self.path.at_depth(index_depth).unwrap();

        let children = self.index.build_node(self.value, path_node);
        self.value = Rpo256::merge(&children);
        self.index.move_up();

        Some(InnerNodeInfo {
            value: self.value,
            left: children[0],
            right: children[1],
        })
    }
}

// COMPARISONS
// ================================================================================================
impl PartialEq<MerklePath> for SparseMerklePath {
    fn eq(&self, rhs: &MerklePath) -> bool {
        if self.depth() != rhs.depth() {
            return false;
        }

        for (node, &rhs_node) in iter::zip(self, rhs.iter()) {
            if node != rhs_node {
                return false;
            }
        }

        true
    }
}

impl PartialEq<SparseMerklePath> for MerklePath {
    fn eq(&self, rhs: &SparseMerklePath) -> bool {
        rhs == self
    }
}

// SPARSE VALUE PATH
// ================================================================================================
/// A container for a [crate::Word] value and its [SparseMerklePath] opening.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparseValuePath {
    /// The node value opening for `path`.
    pub value: Word,
    /// The path from `value` to `root` (exclusive), using an efficient memory representation for
    /// empty nodes.
    pub path: SparseMerklePath,
}

impl SparseValuePath {
    /// Convenience function to construct a [SparseValuePath].
    ///
    /// `value` is the value `path` leads to, in the tree.
    pub fn new(value: Word, path: SparseMerklePath) -> Self {
        Self { value, path }
    }
}

impl From<(SparseMerklePath, Word)> for SparseValuePath {
    fn from((path, value): (SparseMerklePath, Word)) -> Self {
        SparseValuePath::new(value, path)
    }
}

impl TryFrom<ValuePath> for SparseValuePath {
    type Error = MerkleError;

    /// # Errors
    ///
    /// This conversion returns [MerkleError::DepthTooBig] if the path length is greater than
    /// [`SMT_MAX_DEPTH`].
    fn try_from(other: ValuePath) -> Result<Self, MerkleError> {
        let ValuePath { value, path } = other;
        let path = SparseMerklePath::try_from(path)?;
        Ok(SparseValuePath { value, path })
    }
}

impl From<SparseValuePath> for ValuePath {
    fn from(other: SparseValuePath) -> Self {
        let SparseValuePath { value, path } = other;
        ValuePath { value, path: path.into() }
    }
}

impl PartialEq<ValuePath> for SparseValuePath {
    fn eq(&self, rhs: &ValuePath) -> bool {
        self.value == rhs.value && self.path == rhs.path
    }
}

impl PartialEq<SparseValuePath> for ValuePath {
    fn eq(&self, rhs: &SparseValuePath) -> bool {
        rhs == self
    }
}

// HELPERS
// ================================================================================================

/// Iterator for path depths, which start at the deepest part of the tree and go the shallowest
/// depth before the root (depth 1).
fn path_depth_iter(tree_depth: u8) -> impl ExactSizeIterator<Item = NonZero<u8>> {
    let top_down_iter = (1..=tree_depth).map(|depth| {
        // SAFETY: `RangeInclusive<1, _>` cannot ever yield 0. Even if `tree_depth` is 0, then the
        // range is `RangeInclusive<1, 0>` will simply not yield any values, and this block won't
        // even be reached.
        unsafe { NonZero::new_unchecked(depth) }
    });

    // Reverse the top-down iterator to get a bottom-up iterator.
    top_down_iter.rev()
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::num::NonZero;

    use assert_matches::assert_matches;

    use super::SparseMerklePath;
    use crate::{
        Felt, ONE, Word,
        merkle::{
            EmptySubtreeRoots, MerkleError, MerklePath, NodeIndex, SMT_DEPTH, Smt,
            smt::SparseMerkleTree, sparse_path::path_depth_iter,
        },
    };

    fn make_smt(pair_count: u64) -> Smt {
        let entries: Vec<(Word, Word)> = (0..pair_count)
            .map(|n| {
                let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                let key = Word::new([ONE, ONE, Felt::new(n), Felt::new(leaf_index)]);
                let value = Word::new([ONE, ONE, ONE, ONE]);
                (key, value)
            })
            .collect();

        Smt::with_entries(entries).unwrap()
    }

    #[test]
    fn test_roundtrip() {
        let tree = make_smt(8192);

        for (key, _value) in tree.entries() {
            let (control_path, _) = tree.open(key).into_parts();
            assert_eq!(control_path.len(), tree.depth() as usize);

            let sparse_path = SparseMerklePath::try_from(control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());
            assert_eq!(sparse_path.depth(), SMT_DEPTH);
            let test_path = MerklePath::from_iter(sparse_path.clone().into_iter());

            assert_eq!(control_path, test_path);
        }
    }

    /// Manually test the exact bit patterns for a sample path of 8 nodes, including both empty and
    /// non-empty nodes.
    ///
    /// This also offers an overview of what each part of the bit-math involved means and
    /// represents.
    #[test]
    fn test_sparse_bits() {
        const DEPTH: u8 = 8;
        let raw_nodes: [Word; DEPTH as usize] = [
            // Depth 8.
            ([8u8, 8, 8, 8].into()),
            // Depth 7.
            *EmptySubtreeRoots::entry(DEPTH, 7),
            // Depth 6.
            *EmptySubtreeRoots::entry(DEPTH, 6),
            // Depth 5.
            [5u8, 5, 5, 5].into(),
            // Depth 4.
            [4u8, 4, 4, 4].into(),
            // Depth 3.
            *EmptySubtreeRoots::entry(DEPTH, 3),
            // Depth 2.
            *EmptySubtreeRoots::entry(DEPTH, 2),
            // Depth 1.
            *EmptySubtreeRoots::entry(DEPTH, 1),
            // Root is not included.
        ];

        let sparse_nodes: [Option<Word>; DEPTH as usize] = [
            // Depth 8.
            Some([8u8, 8, 8, 8].into()),
            // Depth 7.
            None,
            // Depth 6.
            None,
            // Depth 5.
            Some([5u8, 5, 5, 5].into()),
            // Depth 4.
            Some([4u8, 4, 4, 4].into()),
            // Depth 3.
            None,
            // Depth 2.
            None,
            // Depth 1.
            None,
            // Root is not included.
        ];

        const EMPTY_BITS: u64 = 0b0110_0111;

        let sparse_path = SparseMerklePath::from_sized_iter(raw_nodes).unwrap();

        assert_eq!(sparse_path.empty_nodes_mask, EMPTY_BITS);

        // Keep track of how many non-empty nodes we have seen
        let mut nonempty_idx = 0;

        // Test starting from the deepest nodes (depth 8)
        for depth in (1..=8).rev() {
            let idx = (sparse_path.depth() - depth) as usize;
            let bit = 1 << (depth - 1);

            // Check that the depth bit is set correctly...
            let is_set = (sparse_path.empty_nodes_mask & bit) != 0;
            assert_eq!(is_set, sparse_nodes.get(idx).unwrap().is_none());

            if is_set {
                // Check that we don't return digests for empty nodes
                let &test_node = sparse_nodes.get(idx).unwrap();
                assert_eq!(test_node, None);
            } else {
                // Check that we can calculate non-empty indices correctly.
                let control_node = raw_nodes.get(idx).unwrap();
                assert_eq!(
                    sparse_path.get_nonempty_index(NonZero::new(depth).unwrap()).unwrap(),
                    nonempty_idx
                );
                let test_node = sparse_path.nodes.get(nonempty_idx).unwrap();
                assert_eq!(test_node, control_node);

                nonempty_idx += 1;
            }
        }
    }

    #[test]
    fn from_sized_iter() {
        let tree = make_smt(8192);

        for (key, _value) in tree.entries() {
            let index = NodeIndex::from(Smt::key_to_leaf_index(key));

            let control_path = tree.get_path(key);
            for (&control_node, proof_index) in
                itertools::zip_eq(&*control_path, index.proof_indices())
            {
                let proof_node = tree.get_node_hash(proof_index);
                assert_eq!(control_node, proof_node);
            }

            let sparse_path =
                SparseMerklePath::from_sized_iter(control_path.clone().into_iter()).unwrap();
            for (sparse_node, proof_idx) in
                itertools::zip_eq(sparse_path.clone(), index.proof_indices())
            {
                let proof_node = tree.get_node_hash(proof_idx);
                assert_eq!(sparse_node, proof_node);
            }

            assert_eq!(control_path.depth(), sparse_path.depth());
            for (control, sparse) in itertools::zip_eq(control_path, sparse_path) {
                assert_eq!(control, sparse);
            }
        }
    }

    #[test]
    fn test_random_access() {
        let tree = make_smt(8192);

        for (i, (key, _value)) in tree.entries().enumerate() {
            let control_path = tree.get_path(key);
            let sparse_path = SparseMerklePath::try_from(control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());
            assert_eq!(sparse_path.depth(), SMT_DEPTH);

            // Test random access by depth.
            for depth in path_depth_iter(control_path.depth()) {
                let control_node = control_path.at_depth(depth).unwrap();
                let sparse_node = sparse_path.at_depth(depth).unwrap();
                assert_eq!(control_node, sparse_node, "at depth {depth} for entry {i}");
            }
        }
    }

    #[test]
    fn test_borrowing_iterator() {
        let tree = make_smt(8192);

        for (key, _value) in tree.entries() {
            let control_path = tree.get_path(key);
            let sparse_path = SparseMerklePath::try_from(control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());
            assert_eq!(sparse_path.depth(), SMT_DEPTH);

            // Test that both iterators yield the same amount of the same values.
            let mut count: u64 = 0;
            for (&control_node, sparse_node) in
                itertools::zip_eq(control_path.iter(), sparse_path.iter())
            {
                count += 1;
                assert_eq!(control_node, sparse_node);
            }
            assert_eq!(count, control_path.depth() as u64);
        }
    }

    #[test]
    fn test_owning_iterator() {
        let tree = make_smt(8192);

        for (key, _value) in tree.entries() {
            let control_path = tree.get_path(key);
            let path_depth = control_path.depth();
            let sparse_path = SparseMerklePath::try_from(control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());
            assert_eq!(sparse_path.depth(), SMT_DEPTH);

            // Test that both iterators yield the same amount of the same values.
            let mut count: u64 = 0;
            for (control_node, sparse_node) in itertools::zip_eq(control_path, sparse_path) {
                count += 1;
                assert_eq!(control_node, sparse_node);
            }
            assert_eq!(count, path_depth as u64);
        }
    }

    #[test]
    fn test_zero_sized() {
        let nodes: Vec<Word> = Default::default();

        // Sparse paths that don't actually contain any nodes should still be well behaved.
        let sparse_path = SparseMerklePath::from_sized_iter(nodes).unwrap();
        assert_eq!(sparse_path.depth(), 0);
        assert_matches!(
            sparse_path.at_depth(NonZero::new(1).unwrap()),
            Err(MerkleError::DepthTooBig(1))
        );
        assert_eq!(sparse_path.iter().next(), None);
        assert_eq!(sparse_path.into_iter().next(), None);
    }

    #[test]
    fn test_root() {
        let tree = make_smt(100);

        for (key, _value) in tree.entries() {
            let leaf = tree.get_leaf(key);
            let leaf_node = leaf.hash();
            let index: NodeIndex = Smt::key_to_leaf_index(key).into();
            let control_path = tree.get_path(key);
            let sparse_path = SparseMerklePath::try_from(control_path.clone()).unwrap();

            let authed_nodes: Vec<_> =
                sparse_path.authenticated_nodes(index.value(), leaf_node).unwrap().collect();
            let authed_root = authed_nodes.last().unwrap().value;

            let control_root = control_path.compute_root(index.value(), leaf_node).unwrap();
            let sparse_root = sparse_path.compute_root(index.value(), leaf_node).unwrap();
            assert_eq!(control_root, sparse_root);
            assert_eq!(authed_root, control_root);
            assert_eq!(authed_root, tree.root());

            let index = index.value();
            let control_auth_nodes = control_path.authenticated_nodes(index, leaf_node).unwrap();
            let sparse_auth_nodes = sparse_path.authenticated_nodes(index, leaf_node).unwrap();
            for (a, b) in control_auth_nodes.zip(sparse_auth_nodes) {
                assert_eq!(a, b);
            }
        }
    }
}
