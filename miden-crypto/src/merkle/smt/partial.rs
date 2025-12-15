use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use super::{EmptySubtreeRoots, LeafIndex, SMT_DEPTH};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath,
        smt::{InnerNode, InnerNodes, Leaves, SmtLeaf, SmtLeafError, SmtProof},
    },
};

/// A partial version of an [`super::Smt`].
///
/// This type can track a subset of the key-value pairs of a full [`super::Smt`] and allows for
/// updating those pairs to compute the new root of the tree, as if the updates had been done on the
/// full tree. This is useful so that not all leaves have to be present and loaded into memory to
/// compute an update.
///
/// A key is considered "tracked" if either:
/// 1. Its merkle path was explicitly added to the tree (via [`PartialSmt::add_path`] or
///    [`PartialSmt::add_proof`]), or
/// 2. The path from the leaf to the root goes through empty subtrees that are consistent with the
///    stored inner nodes (provably empty with zero hash computations).
///
/// The second condition allows updating keys in empty subtrees without explicitly adding their
/// merkle paths. This is verified by walking up from the leaf and checking that any stored
/// inner node has an empty subtree root as the child on our path.
///
/// An important caveat is that only tracked keys can be updated. Attempting to update an
/// untracked key will result in an error. See [`PartialSmt::insert`] for more details.
///
/// Once a partial SMT has been constructed, its root is set in stone. All subsequently added proofs
/// or merkle paths must match that root, otherwise an error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialSmt {
    root: Word,
    num_entries: usize,
    leaves: Leaves<SmtLeaf>,
    inner_nodes: InnerNodes,
}

impl PartialSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The default value used to compute the hash of empty leaves.
    pub const EMPTY_VALUE: Word = EMPTY_WORD;

    /// The root of an empty tree.
    pub const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialSmt`] from a root.
    ///
    /// All subsequently added proofs or paths must have the same root.
    pub fn new(root: Word) -> Self {
        Self {
            root,
            num_entries: 0,
            leaves: Leaves::<SmtLeaf>::default(),
            inner_nodes: InnerNodes::default(),
        }
    }

    /// Instantiates a new [`PartialSmt`] by calling [`PartialSmt::add_proof`] for all [`SmtProof`]s
    /// in the provided iterator.
    ///
    /// If the provided iterator is empty, an empty [`PartialSmt`] is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the roots of the provided proofs are not the same.
    pub fn from_proofs<I>(proofs: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut proofs = proofs.into_iter();

        let Some(first_proof) = proofs.next() else {
            return Ok(Self::default());
        };

        // Add the first path to an empty partial SMT without checking that the existing root
        // matches the new one. This sets the expected root to the root of the first proof and all
        // subsequently added proofs must match it.
        let mut partial_smt = Self::default();
        let (path, leaf) = first_proof.into_parts();
        let path_root = partial_smt.add_path_unchecked(leaf, path);
        partial_smt.root = path_root;

        for proof in proofs {
            partial_smt.add_proof(proof)?;
        }

        Ok(partial_smt)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.root
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn open(&self, key: &Word) -> Result<SmtProof, MerkleError> {
        let leaf = self.get_leaf(key)?;
        let merkle_path = self.get_path(key);
        Ok(SmtProof::new_unchecked(merkle_path, leaf))
    }

    /// Returns the leaf to which `key` maps.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_leaf(&self, key: &Word) -> Result<SmtLeaf, MerkleError> {
        self.get_tracked_leaf(key).ok_or(MerkleError::UntrackedKey(*key))
    }

    /// Returns the value associated with `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_value(&self, key: &Word) -> Result<Word, MerkleError> {
        self.get_tracked_leaf(key)
            .map(|leaf| leaf.get_value(key).unwrap_or_default())
            .ok_or(MerkleError::UntrackedKey(*key))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked (see the type documentation for the definition of "tracked"). If an
    ///   error is returned the tree is in the same state as before.
    /// - inserting the key-value pair would exceed [`super::MAX_LEAF_ENTRIES`] (1024 entries) in
    ///   the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        let current_leaf = self.get_tracked_leaf(&key).ok_or(MerkleError::UntrackedKey(key))?;
        let leaf_index = current_leaf.index();
        let previous_value = current_leaf.get_value(&key).unwrap_or(EMPTY_WORD);
        let prev_entries = current_leaf.num_entries();

        let leaf = self
            .leaves
            .entry(leaf_index.value())
            .or_insert_with(|| SmtLeaf::new_empty(leaf_index));

        if value != EMPTY_WORD {
            leaf.insert(key, value).map_err(|e| match e {
                SmtLeafError::TooManyLeafEntries { actual } => {
                    MerkleError::TooManyLeafEntries { actual }
                },
                other => panic!("unexpected SmtLeaf::insert error: {:?}", other),
            })?;
        } else {
            leaf.remove(key);
        }
        let current_entries = leaf.num_entries();
        self.num_entries = self.num_entries + current_entries - prev_entries;

        // Recompute the path from leaf to root
        let new_leaf_hash = leaf.hash();
        self.recompute_nodes_from_leaf_to_root(leaf_index, new_leaf_hash);

        Ok(previous_value)
    }

    /// Adds an [`SmtProof`] to this [`PartialSmt`].
    ///
    /// This is a convenience method which calls [`Self::add_path`] on the proof. See its
    /// documentation for details on errors.
    pub fn add_proof(&mut self, proof: SmtProof) -> Result<(), MerkleError> {
        let (path, leaf) = proof.into_parts();
        self.add_path(leaf, path)
    }

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`].
    ///
    /// If this function was called, any key that is part of the `leaf` can subsequently be updated
    /// to a new value and produce a correct new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing
    ///   root. If an error is returned, the tree is left in an inconsistent state.
    pub fn add_path(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Result<(), MerkleError> {
        let path_root = self.add_path_unchecked(leaf, path);

        // Check if the newly added merkle path is consistent with the existing tree. If not, the
        // merkle path was invalid or computed against another tree.
        if self.root() != path_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: path_root,
            });
        }

        Ok(())
    }

    /// Returns an iterator over the inner nodes of the [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    /// Returns an iterator over the [`InnerNode`] and the respective [`NodeIndex`] of the
    /// [`PartialSmt`].
    pub fn inner_node_indices(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        self.inner_nodes.iter().map(|(idx, inner)| (*idx, inner.clone()))
    }

    /// Returns an iterator over the explicitly stored, non-empty leaves of the [`PartialSmt`] in
    /// arbitrary order.
    ///
    /// Note: This only returns leaves that were explicitly added via [`Self::add_path`] or
    /// [`Self::add_proof`], or created through [`Self::insert`]. It does not include implicitly
    /// trackable leaves in empty subtrees.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .filter(|(_, leaf)| !leaf.is_empty())
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the tracked, non-empty key-value pairs of the [`PartialSmt`] in
    /// arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns the number of tracked leaves in this tree, which includes empty ones.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the number of tracked, non-empty key-value pairs in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Returns a boolean value indicating whether the [`PartialSmt`] tracks any leaves.
    ///
    /// Note that if a partial SMT does not track leaves, its root is not necessarily the empty SMT
    /// root, since it could have been constructed from a different root but without tracking any
    /// leaves.
    pub fn tracks_leaves(&self) -> bool {
        !self.leaves.is_empty()
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`] and returns the root of the
    /// inserted path.
    ///
    /// This does not check that the path root matches the existing root of the tree and if so, the
    /// tree is left in an inconsistent state. This state can be made consistent again by setting
    /// the root of the SMT to the path root.
    fn add_path_unchecked(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Word {
        let mut current_index = leaf.index().index;

        let mut node_hash_at_current_index = leaf.hash();

        let prev_entries = self
            .leaves
            .get(&current_index.value())
            .map(|leaf| leaf.num_entries())
            .unwrap_or(0);
        let current_entries = leaf.num_entries();
        // We insert even empty leaves into the leaves map. While not strictly necessary for
        // tracking (empty leaves are implicitly trackable), storing them preserves the merkle
        // path information and avoids the cost of implicit tracking lookups for these leaves.
        self.leaves.insert(current_index.value(), leaf);

        // Guaranteed not to over/underflow. All variables are <= MAX_LEAF_ENTRIES and result > 0.
        self.num_entries = self.num_entries + current_entries - prev_entries;

        for sibling_hash in path {
            // Find the index of the sibling node and compute whether it is a left or right child.
            let is_sibling_right = current_index.sibling().is_value_odd();

            // Move the index up so it points to the parent of the current index and the sibling.
            current_index.move_up();

            // Construct the new parent node from the child that was updated and the sibling from
            // the merkle path.
            let new_parent_node = if is_sibling_right {
                InnerNode {
                    left: node_hash_at_current_index,
                    right: sibling_hash,
                }
            } else {
                InnerNode {
                    left: sibling_hash,
                    right: node_hash_at_current_index,
                }
            };

            node_hash_at_current_index = new_parent_node.hash();

            self.insert_inner_node(current_index, new_parent_node);
        }

        node_hash_at_current_index
    }

    /// Returns the leaf for a key if it can be tracked.
    ///
    /// A key is trackable if:
    /// 1. It was explicitly added via `add_path`/`add_proof`, OR
    /// 2. The path to the leaf goes through empty subtrees (provably empty)
    ///
    /// Returns `None` if the key cannot be tracked (path goes through non-empty
    /// subtrees we don't have data for).
    fn get_tracked_leaf(&self, key: &Word) -> Option<SmtLeaf> {
        let leaf_index = Self::key_to_leaf_index(key);

        // Explicitly stored leaves are always trackable
        if let Some(leaf) = self.leaves.get(&leaf_index.value()) {
            return Some(leaf.clone());
        }

        // Check if we can reach this leaf through empty subtrees
        let mut index: NodeIndex = leaf_index.into();

        while index.depth() > 0 {
            if let Some(parent) = self.get_inner_node(index.parent()) {
                // Found a stored inner node - child must be empty subtree root
                let child_hash = if index.is_value_odd() {
                    parent.right
                } else {
                    parent.left
                };
                if child_hash == *EmptySubtreeRoots::entry(SMT_DEPTH, index.depth()) {
                    return Some(SmtLeaf::new_empty(leaf_index));
                }
                return None; // Non-empty child we don't have data for
            }
            index.move_up();
        }

        // Reached root through all unstored nodes - implicitly empty
        Some(SmtLeaf::new_empty(leaf_index))
    }

    /// Converts a key to a leaf index.
    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    /// Returns the inner node at the specified index, or `None` if not stored.
    fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.get(&index).cloned()
    }

    /// Returns the inner node at the specified index, falling back to the empty subtree root
    /// if not stored.
    fn get_inner_node_or_empty(&self, index: NodeIndex) -> InnerNode {
        self.get_inner_node(index)
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    /// Inserts an inner node at the specified index.
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        if inner_node == EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()) {
            self.inner_nodes.remove(&index);
        } else {
            self.inner_nodes.insert(index, inner_node);
        }
    }

    /// Returns the merkle path for a key by walking up the tree from the leaf.
    fn get_path(&self, key: &Word) -> SparseMerklePath {
        let index = NodeIndex::from(Self::key_to_leaf_index(key));

        // Use proof_indices to get sibling indices from leaf to root,
        // and get each sibling's hash
        SparseMerklePath::from_sized_iter(index.proof_indices().map(|idx| self.get_node_hash(idx)))
            .expect("path should be valid since it's from a valid SMT")
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns the root. Other hashes are retrieved by looking at
    /// the parent inner node and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root;
        }

        let InnerNode { left, right } = self.get_inner_node_or_empty(index.parent());

        if index.is_value_odd() { right } else { left }
    }

    /// Recomputes all inner nodes from a leaf up to the root after a leaf value change.
    fn recompute_nodes_from_leaf_to_root(
        &mut self,
        leaf_index: LeafIndex<SMT_DEPTH>,
        leaf_hash: Word,
    ) {
        use crate::hash::rpo::Rpo256;

        let mut index: NodeIndex = leaf_index.into();
        let mut node_hash = leaf_hash;

        for _ in (0..index.depth()).rev() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node_or_empty(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Rpo256::merge(&[left, right]);

            // insert_inner_node handles removing empty subtree roots
            self.insert_inner_node(index, InnerNode { left, right });
        }
        self.root = node_hash;
    }

    /// Validates the internal structure during deserialization.
    ///
    /// Checks that:
    /// - Each inner node's hash is consistent with its parent.
    /// - Each leaf's hash is consistent with its parent inner node's left/right child.
    fn validate(&self) -> Result<(), DeserializationError> {
        // Validate each inner node is consistent with its parent
        for (&idx, node) in &self.inner_nodes {
            let node_hash = node.hash();
            let expected_hash = self.get_node_hash(idx);

            if node_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "inner node hash is inconsistent with parent".into(),
                ));
            }
        }

        // Validate each leaf's hash is consistent with its parent inner node
        for (&leaf_pos, leaf) in &self.leaves {
            let leaf_index = LeafIndex::<SMT_DEPTH>::new_max_depth(leaf_pos);
            let node_index: NodeIndex = leaf_index.into();
            let leaf_hash = leaf.hash();
            let expected_hash = self.get_node_hash(node_index);

            if leaf_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "leaf hash is inconsistent with parent inner node".into(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for PartialSmt {
    /// Returns a new, empty [`PartialSmt`].
    ///
    /// All leaves in the returned tree are set to [`Self::EMPTY_VALUE`].
    fn default() -> Self {
        Self::new(Self::EMPTY_ROOT)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<super::Smt> for PartialSmt {
    fn from(smt: super::Smt) -> Self {
        Self {
            root: smt.root(),
            num_entries: smt.num_entries(),
            leaves: smt.leaves().map(|(idx, leaf)| (idx.value(), leaf.clone())).collect(),
            inner_nodes: smt.inner_node_indices().collect(),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialSmt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.root());
        target.write_usize(self.leaves.len());
        for (i, leaf) in &self.leaves {
            target.write_u64(*i);
            target.write(leaf);
        }
        target.write_usize(self.inner_nodes.len());
        for (idx, node) in &self.inner_nodes {
            target.write(idx);
            target.write(node);
        }
    }
}

impl Deserializable for PartialSmt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let root: Word = source.read()?;

        let mut leaves = Leaves::<SmtLeaf>::default();
        for _ in 0..source.read_usize()? {
            let pos: u64 = source.read()?;
            let leaf: SmtLeaf = source.read()?;
            leaves.insert(pos, leaf);
        }

        let mut inner_nodes = InnerNodes::default();
        for _ in 0..source.read_usize()? {
            let idx: NodeIndex = source.read()?;
            let node: InnerNode = source.read()?;
            inner_nodes.insert(idx, node);
        }

        let num_entries = leaves.values().map(|leaf| leaf.num_entries()).sum();

        let partial = Self { root, num_entries, leaves, inner_nodes };
        partial.validate()?;

        Ok(partial)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use alloc::collections::{BTreeMap, BTreeSet};

    use assert_matches::assert_matches;
    use rand_utils::{rand_array, rand_value};
    use winter_math::fields::f64::BaseElement as Felt;

    use super::*;
    use crate::{
        EMPTY_WORD, ONE, ZERO,
        merkle::{EmptySubtreeRoots, smt::Smt},
    };

    /// Tests that a partial SMT constructed from a root is well behaved and returns expected
    /// values.
    #[test]
    fn partial_smt_new_with_no_entries() {
        let key0 = Word::from(rand_array::<Felt, 4>());
        let value0 = Word::from(rand_array::<Felt, 4>());
        let full = Smt::with_entries([(key0, value0)]).unwrap();

        let partial_smt = PartialSmt::new(full.root());

        assert!(!partial_smt.tracks_leaves());
        assert_eq!(partial_smt.num_entries(), 0);
        assert_eq!(partial_smt.num_leaves(), 0);
        assert_eq!(partial_smt.entries().count(), 0);
        assert_eq!(partial_smt.leaves().count(), 0);
        assert_eq!(partial_smt.root(), full.root());
    }

    /// Tests that a basic PartialSmt can be built from a full one and that inserting or removing
    /// values whose merkle path were added to the partial SMT results in the same root as the
    /// equivalent update in the full tree.
    #[test]
    fn partial_smt_insert_and_remove() {
        let key0 = Word::from(rand_array::<Felt, 4>());
        let key1 = Word::from(rand_array::<Felt, 4>());
        let key2 = Word::from(rand_array::<Felt, 4>());
        // A key for which we won't add a value so it will be empty.
        let key_empty = Word::from(rand_array::<Felt, 4>());

        let value0 = Word::from(rand_array::<Felt, 4>());
        let value1 = Word::from(rand_array::<Felt, 4>());
        let value2 = Word::from(rand_array::<Felt, 4>());

        let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

        // Add more random leaves.
        kv_pairs.reserve(1000);
        for _ in 0..1000 {
            let key = Word::from(rand_array::<Felt, 4>());
            let value = Word::from(rand_array::<Felt, 4>());
            kv_pairs.push((key, value));
        }

        let mut full = Smt::with_entries(kv_pairs).unwrap();

        // Constructing a partial SMT from proofs succeeds.
        // ----------------------------------------------------------------------------------------

        let proof0 = full.open(&key0);
        let proof2 = full.open(&key2);
        let proof_empty = full.open(&key_empty);

        assert!(proof_empty.leaf().is_empty());

        let mut partial = PartialSmt::from_proofs([proof0, proof2, proof_empty]).unwrap();

        assert_eq!(full.root(), partial.root());
        assert_eq!(partial.get_value(&key0).unwrap(), value0);
        let error = partial.get_value(&key1).unwrap_err();
        assert_matches!(error, MerkleError::UntrackedKey(_));
        assert_eq!(partial.get_value(&key2).unwrap(), value2);

        // Insert new values for added keys with empty and non-empty values.
        // ----------------------------------------------------------------------------------------

        let new_value0 = Word::from(rand_array::<Felt, 4>());
        let new_value2 = Word::from(rand_array::<Felt, 4>());
        // A non-empty value for the key that was previously empty.
        let new_value_empty_key = Word::from(rand_array::<Felt, 4>());

        full.insert(key0, new_value0).unwrap();
        full.insert(key2, new_value2).unwrap();
        full.insert(key_empty, new_value_empty_key).unwrap();

        partial.insert(key0, new_value0).unwrap();
        partial.insert(key2, new_value2).unwrap();
        // This updates a key whose value was previously empty.
        partial.insert(key_empty, new_value_empty_key).unwrap();

        assert_eq!(full.root(), partial.root());
        assert_eq!(partial.get_value(&key0).unwrap(), new_value0);
        assert_eq!(partial.get_value(&key2).unwrap(), new_value2);
        assert_eq!(partial.get_value(&key_empty).unwrap(), new_value_empty_key);

        // Remove an added key.
        // ----------------------------------------------------------------------------------------

        full.insert(key0, EMPTY_WORD).unwrap();
        partial.insert(key0, EMPTY_WORD).unwrap();

        assert_eq!(full.root(), partial.root());
        assert_eq!(partial.get_value(&key0).unwrap(), EMPTY_WORD);

        // Check if returned openings are the same in partial and full SMT.
        // ----------------------------------------------------------------------------------------

        // This is a key whose value is empty since it was removed.
        assert_eq!(full.open(&key0), partial.open(&key0).unwrap());
        // This is a key whose value is non-empty.
        assert_eq!(full.open(&key2), partial.open(&key2).unwrap());

        // Attempting to update a key whose merkle path was not added is an error.
        // ----------------------------------------------------------------------------------------

        let error = partial.clone().insert(key1, Word::from(rand_array::<Felt, 4>())).unwrap_err();
        assert_matches!(error, MerkleError::UntrackedKey(_));

        let error = partial.insert(key1, EMPTY_WORD).unwrap_err();
        assert_matches!(error, MerkleError::UntrackedKey(_));
    }

    /// Test that we can add an SmtLeaf::Multiple variant to a partial SMT.
    #[test]
    fn partial_smt_multiple_leaf_success() {
        // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
        let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
        let key1 = Word::from([ONE, ONE, ONE, ONE]);
        let key2 = Word::from(rand_array::<Felt, 4>());

        let value0 = Word::from(rand_array::<Felt, 4>());
        let value1 = Word::from(rand_array::<Felt, 4>());
        let value2 = Word::from(rand_array::<Felt, 4>());

        let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();

        // Make sure our assumption about the leaf being a multiple is correct.
        let SmtLeaf::Multiple(_) = full.get_leaf(&key0) else {
            panic!("expected full tree to produce multiple leaf")
        };

        let proof0 = full.open(&key0);
        let proof2 = full.open(&key2);

        let partial = PartialSmt::from_proofs([proof0, proof2]).unwrap();

        assert_eq!(partial.root(), full.root());

        assert_eq!(partial.get_leaf(&key0).unwrap(), full.get_leaf(&key0));
        // key1 is present in the partial tree because it is part of the proof of key0.
        assert_eq!(partial.get_leaf(&key1).unwrap(), full.get_leaf(&key1));
        assert_eq!(partial.get_leaf(&key2).unwrap(), full.get_leaf(&key2));
    }

    /// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
    /// error.
    ///
    /// This test uses only empty values in the partial SMT.
    #[test]
    fn partial_smt_root_mismatch_on_empty_values() {
        let key0 = Word::from(rand_array::<Felt, 4>());
        let key1 = Word::from(rand_array::<Felt, 4>());
        let key2 = Word::from(rand_array::<Felt, 4>());

        let value0 = EMPTY_WORD;
        let value1 = Word::from(rand_array::<Felt, 4>());
        let value2 = EMPTY_WORD;

        let kv_pairs = vec![(key0, value0)];

        let mut full = Smt::with_entries(kv_pairs).unwrap();

        // This proof will become stale after the tree is modified.
        let stale_proof = full.open(&key2);

        // Insert a non-empty value so the root actually changes.
        full.insert(key1, value1).unwrap();
        full.insert(key2, value2).unwrap();

        // Construct a partial SMT against the latest root.
        let mut partial = PartialSmt::new(full.root());

        // Adding the stale proof should fail as its root is different.
        let err = partial.add_proof(stale_proof).unwrap_err();
        assert_matches!(err, MerkleError::ConflictingRoots { .. });
    }

    /// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
    /// error.
    ///
    /// This test uses only non-empty values in the partial SMT.
    #[test]
    fn partial_smt_root_mismatch_on_non_empty_values() {
        let key0 = Word::new(rand_array());
        let key1 = Word::new(rand_array());
        let key2 = Word::new(rand_array());

        let value0 = Word::new(rand_array());
        let value1 = Word::new(rand_array());
        let value2 = Word::new(rand_array());

        let kv_pairs = vec![(key0, value0), (key1, value1)];

        let mut full = Smt::with_entries(kv_pairs).unwrap();

        // This proof will become stale after the tree is modified.
        let stale_proof = full.open(&key0);

        // Insert a value so the root changes.
        full.insert(key2, value2).unwrap();

        // Construct a partial SMT against the latest root.
        let mut partial = PartialSmt::new(full.root());

        // Adding the stale proof should fail as its root is different.
        let err = partial.add_proof(stale_proof).unwrap_err();
        assert_matches!(err, MerkleError::ConflictingRoots { .. });
    }

    /// Tests that from_proofs fails when the proofs roots do not match.
    #[test]
    fn partial_smt_from_proofs_fails_on_root_mismatch() {
        let key0 = Word::new(rand_array());
        let key1 = Word::new(rand_array());

        let value0 = Word::new(rand_array());
        let value1 = Word::new(rand_array());

        let mut full = Smt::with_entries([(key0, value0)]).unwrap();

        // This proof will become stale after the tree is modified.
        let stale_proof = full.open(&key0);

        // Insert a value so the root changes.
        full.insert(key1, value1).unwrap();

        // Construct a partial SMT against the latest root.
        let err = PartialSmt::from_proofs([full.open(&key1), stale_proof]).unwrap_err();
        assert_matches!(err, MerkleError::ConflictingRoots { .. });
    }

    /// Tests that a basic PartialSmt's iterator APIs return the expected values.
    #[test]
    fn partial_smt_iterator_apis() {
        let key0 = Word::new(rand_array());
        let key1 = Word::new(rand_array());
        let key2 = Word::new(rand_array());
        // A key for which we won't add a value so it will be empty.
        let key_empty = Word::new(rand_array());

        let value0 = Word::new(rand_array());
        let value1 = Word::new(rand_array());
        let value2 = Word::new(rand_array());

        let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

        // Add more random leaves.
        kv_pairs.reserve(1000);
        for _ in 0..1000 {
            let key = Word::new(rand_array());
            let value = Word::new(rand_array());
            kv_pairs.push((key, value));
        }

        let full = Smt::with_entries(kv_pairs).unwrap();

        // Construct a partial SMT from proofs.
        // ----------------------------------------------------------------------------------------

        let proof0 = full.open(&key0);
        let proof2 = full.open(&key2);
        let proof_empty = full.open(&key_empty);

        assert!(proof_empty.leaf().is_empty());

        let proofs = [proof0, proof2, proof_empty];
        let partial = PartialSmt::from_proofs(proofs.clone()).unwrap();

        assert!(partial.tracks_leaves());
        assert_eq!(full.root(), partial.root());
        // There should be 2 non-empty entries.
        assert_eq!(partial.num_entries(), 2);
        // There should be 3 leaves, including the empty one.
        assert_eq!(partial.num_leaves(), 3);

        // The leaves API should only return tracked but non-empty leaves.
        // ----------------------------------------------------------------------------------------

        // Construct the sorted vector of leaves that should be yielded by the partial SMT.
        let expected_leaves: BTreeMap<_, _> =
            [SmtLeaf::new_single(key0, value0), SmtLeaf::new_single(key2, value2)]
                .into_iter()
                .map(|leaf| (leaf.index(), leaf))
                .collect();

        let actual_leaves = partial
            .leaves()
            .map(|(idx, leaf)| (idx, leaf.clone()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(actual_leaves.len(), expected_leaves.len());
        assert_eq!(actual_leaves, expected_leaves);

        // The num_leaves API should return the count of explicitly stored leaves including empty.
        // ----------------------------------------------------------------------------------------

        // We added 3 proofs (key0, key2, key_empty), so num_leaves should be 3.
        assert_eq!(partial.num_leaves(), 3);

        // The entries of the merkle paths from the proofs should exist as children of inner nodes
        // in the partial SMT.
        // ----------------------------------------------------------------------------------------

        let partial_inner_nodes: BTreeSet<_> =
            partial.inner_nodes().flat_map(|node| [node.left, node.right]).collect();
        let empty_subtree_roots: BTreeSet<_> = (0..SMT_DEPTH)
            .map(|depth| *EmptySubtreeRoots::entry(SMT_DEPTH, depth))
            .collect();

        for merkle_path in proofs.into_iter().map(|proof| proof.into_parts().0) {
            for (idx, digest) in merkle_path.into_iter().enumerate() {
                assert!(
                    partial_inner_nodes.contains(&digest) || empty_subtree_roots.contains(&digest),
                    "failed at idx {idx}"
                );
            }
        }
    }

    /// Test that the default partial SMT's tracks_leaves method returns `false`.
    #[test]
    fn partial_smt_tracks_leaves() {
        assert!(!PartialSmt::default().tracks_leaves());
    }

    /// `PartialSmt` serde round-trip when constructed from just a root.
    #[test]
    fn partial_smt_with_empty_leaves_serialization_roundtrip() {
        let partial_smt = PartialSmt::new(rand_value());
        assert_eq!(partial_smt, PartialSmt::read_from_bytes(&partial_smt.to_bytes()).unwrap());
    }

    /// `PartialSmt` serde round-trip. Also tests conversion from SMT.
    #[test]
    fn partial_smt_serialization_roundtrip() {
        let key = rand_value();
        let val = rand_value();

        let key_1 = rand_value();
        let val_1 = rand_value();

        let key_2 = rand_value();
        let val_2 = rand_value();

        let smt: Smt = Smt::with_entries([(key, val), (key_1, val_1), (key_2, val_2)]).unwrap();

        let partial_smt = PartialSmt::from_proofs([smt.open(&key)]).unwrap();

        assert_eq!(partial_smt.root(), smt.root());
        assert_matches!(partial_smt.open(&key_1), Err(MerkleError::UntrackedKey(_)));
        assert_matches!(partial_smt.open(&key), Ok(_));

        let bytes = partial_smt.to_bytes();
        let decoded = PartialSmt::read_from_bytes(&bytes).unwrap();

        assert_eq!(partial_smt, decoded);
    }

    /// Tests that add_path correctly updates num_entries for increasing entry counts.
    ///
    /// Note that decreasing counts are not possible with the current API.
    #[test]
    fn partial_smt_add_proof_num_entries() {
        // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
        let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
        let key1 = Word::from([ONE, ONE, ONE, ONE]);
        let key2 = Word::from([ONE, ONE, ONE, Felt::new(5)]);
        let value0 = Word::from(rand_array::<Felt, 4>());
        let value1 = Word::from(rand_array::<Felt, 4>());
        let value2 = Word::from(rand_array::<Felt, 4>());

        let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();
        let mut partial = PartialSmt::new(full.root());

        // Add the multi-entry leaf
        partial.add_proof(full.open(&key0)).unwrap();
        assert_eq!(partial.num_entries(), 2);

        // Add the single-entry leaf
        partial.add_proof(full.open(&key2)).unwrap();
        assert_eq!(partial.num_entries(), 3);

        // Setting a value to the empty word removes decreases the number of entries.
        partial.insert(key0, Word::empty()).unwrap();
        assert_eq!(partial.num_entries(), 2);
    }

    /// Tests implicit tracking of empty subtrees based on the visualization from PR #375.
    ///
    /// ```text
    ///              g (root)
    ///            /      \
    ///          e          f
    ///         / \        / \
    ///        a   b      c   d
    ///       /\ /\      /\  /\
    ///      0 1 2 3    4 5 6 7
    /// ```
    ///
    /// State:
    /// - Subtree f is entirely empty.
    /// - Key 1 has a value and a proof in the partial SMT.
    /// - Key 3 has a value but is missing from the partial SMT (making node b non-empty).
    /// - Keys 0, 2, 4, 5, 6, 7 are empty.
    ///
    /// Expected:
    /// - Key 1: CAN update (explicitly tracked via proof)
    /// - Key 0: CAN update (sibling of key 1, provably empty)
    /// - Keys 4, 5, 6, 7: CAN update (in empty subtree f, provably empty)
    /// - Keys 2, 3: CANNOT update (under non-empty node b, only have its hash)
    #[test]
    fn partial_smt_tracking_visualization() {
        // Situation in the diagram mapped to depth-64 SMT.
        const LEAF_0: u64 = 0;
        const LEAF_1: u64 = 1 << 61;
        const LEAF_2: u64 = 1 << 62;
        const LEAF_3: u64 = (1 << 62) | (1 << 61);
        const LEAF_4: u64 = 1 << 63;
        const LEAF_5: u64 = (1 << 63) | (1 << 61);
        const LEAF_6: u64 = (1 << 63) | (1 << 62);
        const LEAF_7: u64 = (1 << 63) | (1 << 62) | (1 << 61);

        let key_0 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_0)]);
        let key_1 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_1)]);
        let key_2 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_2)]);
        let key_3 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_3)]);
        let key_4 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_4)]);
        let key_5 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_5)]);
        let key_6 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_6)]);
        let key_7 = Word::from([ZERO, ZERO, ZERO, Felt::new(LEAF_7)]);

        // Create full SMT with keys 1 and 3 (key_3 makes node b non-empty)
        let mut full = Smt::with_entries([(key_1, rand_value()), (key_3, rand_value())]).unwrap();

        // Create partial SMT with ONLY the proof for key 1
        let proof_1 = full.open(&key_1);
        let mut partial = PartialSmt::from_proofs([proof_1]).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 1: CAN update (explicitly tracked via proof)
        let new_value_1: Word = rand_value();
        full.insert(key_1, new_value_1).unwrap();
        partial.insert(key_1, new_value_1).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 0: CAN update (sibling of key 1, empty)
        let value_0: Word = rand_value();
        full.insert(key_0, value_0).unwrap();
        partial.insert(key_0, value_0).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 4: CAN update (in empty subtree f)
        let value_4: Word = rand_value();
        full.insert(key_4, value_4).unwrap();
        partial.insert(key_4, value_4).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 5: CAN update (in empty subtree f)
        let value_5: Word = rand_value();
        full.insert(key_5, value_5).unwrap();
        partial.insert(key_5, value_5).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 6: CAN update (in empty subtree f)
        let value_6: Word = rand_value();
        full.insert(key_6, value_6).unwrap();
        partial.insert(key_6, value_6).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 7: CAN update (in empty subtree f)
        let value_7: Word = rand_value();
        full.insert(key_7, value_7).unwrap();
        partial.insert(key_7, value_7).unwrap();
        assert_eq!(full.root(), partial.root());

        // Key 2: CANNOT update (under non-empty node b, only have its hash)
        let result = partial.insert(key_2, rand_value());
        assert_matches!(result, Err(MerkleError::UntrackedKey(_)));

        // Key 3: CANNOT update (has data but no proof in partial SMT)
        let result = partial.insert(key_3, rand_value());
        assert_matches!(result, Err(MerkleError::UntrackedKey(_)));
    }

    #[test]
    fn partial_smt_implicit_empty_tree() {
        let mut full = Smt::new();
        let mut partial = PartialSmt::new(full.root());

        let key: Word = rand_value();
        let value: Word = rand_value();

        full.insert(key, value).unwrap();
        // Can insert into empty partial SMT (implicitly tracked)
        partial.insert(key, value).unwrap();

        assert_eq!(full.root(), partial.root());
        assert_eq!(partial.get_value(&key).unwrap(), value);
    }

    #[test]
    fn partial_smt_implicit_insert_and_remove() {
        let mut full = Smt::new();
        let mut partial = PartialSmt::new(full.root());

        let key: Word = rand_value();
        let value: Word = rand_value();

        // Insert into implicitly tracked leaf
        full.insert(key, value).unwrap();
        partial.insert(key, value).unwrap();
        assert_eq!(full.root(), partial.root());

        // Remove the value we just inserted
        full.insert(key, EMPTY_WORD).unwrap();
        partial.insert(key, EMPTY_WORD).unwrap();
        assert_eq!(full.root(), partial.root());
        assert_eq!(partial.get_value(&key).unwrap(), EMPTY_WORD);
        assert_eq!(partial.num_entries(), 0);
    }
}
