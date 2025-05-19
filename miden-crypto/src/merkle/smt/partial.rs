use crate::{
    EMPTY_WORD, Word,
    merkle::{InnerNode, MerkleError, MerklePath, Smt, SmtLeaf, SmtProof, smt::SparseMerkleTree},
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
    pub fn from_proofs<I>(paths: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut partial_smt = Self::new();

        for (path, leaf) in paths.into_iter().map(SmtProof::into_parts) {
            partial_smt.add_path(leaf, path)?;
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
}

impl Default for PartialSmt {
    fn default() -> Self {
        Self::new()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

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
        let key0 = Word::from(rand_array::<Felt, 4>());
        let key1 = Word::from(rand_array::<Felt, 4>());
        let key2 = Word::from(rand_array::<Felt, 4>());

        let value0 = Word::from(rand_array::<Felt, 4>());
        let value1 = Word::from(rand_array::<Felt, 4>());
        let value2 = Word::from(rand_array::<Felt, 4>());

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
}
