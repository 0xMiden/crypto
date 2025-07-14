use winter_utils::{Deserializable, Serializable};

use super::{LeafIndex, SMT_DEPTH};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        InnerNode, InnerNodeInfo, MerkleError, MerklePath, Smt, SmtLeaf, SmtProof,
        smt::SparseMerkleTree,
    },
};

/// A partial version of an [`Smt`].
///
/// This type can track a subset of the key-value pairs of a full [`Smt`] and allows for updating
/// those pairs to compute the new root of the tree, as if the updates had been done on the full
/// tree. This is useful so that not all leaves have to be present and loaded into memory to compute
/// an update.
///
/// To facilitate this, a partial SMT requires that the merkle paths of every key-value pair are
/// added to the tree. This means this pair is considered "tracked" and can be updated.
///
/// An important caveat is that only pairs whose merkle paths were added can be updated. Attempting
/// to update an untracked value will result in an error. See [`PartialSmt::insert`] for more
/// details.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialSmt(Smt);

impl PartialSmt {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`PartialSmt`].
    ///
    /// All leaves in the returned tree are set to [`Smt::EMPTY_VALUE`].
    pub fn new() -> Self {
        Self(Smt::new())
    }

    /// Instantiates a new [`PartialSmt`] by calling [`PartialSmt::add_path`] for all [`SmtProof`]s
    /// in the provided iterator.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of a (leaf, path) tuple does not match the existing root
    ///   (except if the tree was previously empty).
    pub fn from_proofs<I>(proofs: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut partial_smt = Self::new();

        for (proof, leaf) in proofs.into_iter().map(SmtProof::into_parts) {
            partial_smt.add_path(leaf, proof)?;
        }

        Ok(partial_smt)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.0.root()
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn open(&self, key: &Word) -> Result<SmtProof, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.open(key))
    }

    /// Returns the leaf to which `key` maps
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_leaf(&self, key: &Word) -> Result<SmtLeaf, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.get_leaf(key))
    }

    /// Returns the value associated with `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_value(&self, key: &Word) -> Result<Word, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.get_value(key))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Smt::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key and its merkle path were not previously added (using [`PartialSmt::add_path`]) to
    ///   this [`PartialSmt`], which means it is almost certainly incorrect to update its value. If
    ///   an error is returned the tree is in the same state as before.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        if !self.is_leaf_tracked(&key) {
            return Err(MerkleError::UntrackedKey(key));
        }

        let previous_value = self.0.insert(key, value);

        // If the value was removed the SmtLeaf was removed as well by the underlying Smt
        // implementation. However, we still want to consider that leaf tracked so it can be
        // read and written to, so we reinsert an empty SmtLeaf.
        if value == EMPTY_WORD {
            let leaf_index = Smt::key_to_leaf_index(&key);
            self.0.leaves.insert(leaf_index.value(), SmtLeaf::Empty(leaf_index));
        }

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

    /// Adds a leaf and its merkle path to this [`PartialSmt`].
    ///
    /// If this function was called, any key that is part of the `leaf` can subsequently be updated
    /// to a new value and produce a correct new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing root
    ///   (except when the first leaf is added). If an error is returned, the tree is left in an
    ///   inconsistent state.
    pub fn add_path(&mut self, leaf: SmtLeaf, path: MerklePath) -> Result<(), MerkleError> {
        let mut current_index = leaf.index().index;

        let mut node_hash_at_current_index = leaf.hash();

        // We insert directly into the leaves for two reasons:
        // - We can directly insert the leaf as it is without having to loop over its entries to
        //   call Smt::perform_insert.
        // - If the leaf is SmtLeaf::Empty, we will also insert it, which means this leaf is
        //   considered tracked by the partial SMT as it is part of the leaves map. When calling
        //   PartialSmt::insert, this will not error for such empty leaves whose merkle path was
        //   added, but will error for otherwise non-existent leaves whose paths were not added,
        //   which is what we want.
        self.0.leaves.insert(current_index.value(), leaf);

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

            self.0.insert_inner_node(current_index, new_parent_node);

            node_hash_at_current_index = self.0.get_inner_node(current_index).hash();
        }

        // Check the newly added merkle path is consistent with the existing tree. If not, the
        // merkle path was invalid or computed from another tree.
        //
        // We skip this check if we have just inserted the first leaf since we assume that leaf's
        // root is correct and all subsequent leaves that will be added must have the same root.
        if self.0.num_leaves() != 1 && self.root() != node_hash_at_current_index {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: node_hash_at_current_index,
            });
        }

        self.0.set_root(node_hash_at_current_index);

        Ok(())
    }

    /// Returns true if the key's merkle path was previously added to this partial SMT and can be
    /// sensibly updated to a new value.
    /// In particular, this returns true for keys whose value was empty **but** their merkle paths
    /// were added, while it returns false if the merkle paths were **not** added.
    fn is_leaf_tracked(&self, key: &Word) -> bool {
        self.0.leaves.contains_key(&Smt::key_to_leaf_index(key).value())
    }

    /// Returns an iterator over the inner nodes of the [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.0.inner_nodes()
    }

    /// Returns an iterator over the tracked, non-empty leaves of the [`PartialSmt`] in arbitrary
    /// order.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        // The partial SMT also contains empty leaves, so we have to filter them out.
        self.0.leaves().filter_map(
            |(leaf_idx, leaf)| {
                if leaf.is_empty() { None } else { Some((leaf_idx, leaf)) }
            },
        )
    }

    /// Returns an iterator over the tracked leaves of the [`PartialSmt`] in arbitrary order.
    ///
    /// Note that this includes empty leaves.
    pub fn tracked_leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.0.leaves()
    }

    /// Returns an iterator over the tracked, non-empty key-value pairs of the [`PartialSmt`] in
    /// arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.0.entries()
    }

    /// Returns the number of tracked leaves in this tree, which includes empty ones.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.0.num_leaves()
    }

    /// Returns the number of tracked, non-empty key-value pairs in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation as counting the number of
    /// entries requires iterating over all leaves of the tree.
    pub fn num_entries(&self) -> usize {
        self.0.num_entries()
    }

    /// Returns a boolean value indicating whether the [`PartialSmt`] is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for PartialSmt {
    fn default() -> Self {
        Self::new()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Smt> for PartialSmt {
    fn from(smt: Smt) -> Self {
        PartialSmt(smt)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialSmt {
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        target.write(&self.0);
    }
}

impl Deserializable for PartialSmt {
    fn read_from<R: winter_utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, winter_utils::DeserializationError> {
        let inner: Smt = source.read()?;
        Ok(PartialSmt(inner))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use alloc::collections::{BTreeMap, BTreeSet};

    use assert_matches::assert_matches;
    use rand_utils::rand_array;
    use winter_math::fields::f64::BaseElement as Felt;

    use super::*;
    use crate::{EMPTY_WORD, ONE, ZERO};

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

        full.insert(key0, new_value0);
        full.insert(key2, new_value2);
        full.insert(key_empty, new_value_empty_key);

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

        full.insert(key0, EMPTY_WORD);
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
        // This proof will be stale after we insert another value.
        let stale_proof0 = full.open(&key0);

        // Insert a non-empty value so the root actually changes.
        full.insert(key1, value1);
        full.insert(key2, value2);

        let proof2 = full.open(&key2);

        let mut partial = PartialSmt::new();

        partial.add_proof(stale_proof0).unwrap();
        let err = partial.add_proof(proof2).unwrap_err();
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
        // This proof will be stale after we insert another value.
        let stale_proof0 = full.open(&key0);

        full.insert(key2, value2);

        let proof2 = full.open(&key2);

        let mut partial = PartialSmt::new();

        partial.add_proof(stale_proof0).unwrap();
        let err = partial.add_proof(proof2).unwrap_err();
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

        assert!(!partial.is_empty());
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

        // The tracked_leaves API should return all tracked leaves, including empty ones.
        // ----------------------------------------------------------------------------------------

        let mut expected_tracked_leaves = expected_leaves;
        let empty_leaf = SmtLeaf::new_empty(LeafIndex::from(key_empty));
        expected_tracked_leaves.insert(empty_leaf.index(), empty_leaf);

        let actual_tracked_leaves = partial
            .tracked_leaves()
            .map(|(idx, leaf)| (idx, leaf.clone()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(actual_tracked_leaves.len(), expected_tracked_leaves.len());
        assert_eq!(actual_tracked_leaves, expected_tracked_leaves);

        // The entries of the merkle paths from the proofs should exist as children of inner nodes
        // in the partial SMT.
        // ----------------------------------------------------------------------------------------

        let partial_inner_nodes: BTreeSet<_> =
            partial.inner_nodes().flat_map(|node| [node.left, node.right]).collect();

        for merkle_path in proofs.into_iter().map(|proof| proof.into_parts().0) {
            for (idx, digest) in merkle_path.into_iter().enumerate() {
                assert!(partial_inner_nodes.contains(&digest), "failed at idx {idx}");
            }
        }
    }

    /// Test that an empty partial SMT's is_empty method returns `true`.
    #[test]
    fn partial_smt_is_empty() {
        assert!(PartialSmt::new().is_empty());
    }

    /// `PartialSmt` serde round-trip. Also tests conversion from SMT.
    #[test]
    fn partial_smt_serialization_roundtrip() {
        let key = Word::new(rand_array());
        let val = Word::new(rand_array());

        let key_1 = Word::new(rand_array());
        let val_1 = Word::new(rand_array());

        let original: PartialSmt = Smt::with_entries([(key, val), (key_1, val_1)]).unwrap().into();
        let bytes = original.to_bytes();
        let decoded = PartialSmt::read_from_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
