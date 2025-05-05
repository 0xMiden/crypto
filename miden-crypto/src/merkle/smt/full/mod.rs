use alloc::{string::ToString, vec::Vec};

use super::{
    EMPTY_WORD, EmptySubtreeRoots, Felt, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex,
    MerkleError, MerklePath, MutationSet, NodeIndex, Rpo256, RpoDigest, SparseMerkleTree, Word,
};

mod error;
pub use error::{SmtLeafError, SmtProofError};

mod leaf;
pub use leaf::SmtLeaf;

mod proof;
pub use proof::SmtProof;
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

mod large;
pub use large::LargeSmt;

// Concurrent implementation
#[cfg(feature = "concurrent")]
mod concurrent;
#[cfg(feature = "internal")]
pub use concurrent::{SubtreeLeaf, build_subtree_for_bench};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

pub const SMT_DEPTH: u8 = 64;

// SMT
// ================================================================================================

type Leaves = super::Leaves<SmtLeaf>;

/// Sparse Merkle tree mapping 256-bit keys to 256-bit values. Both keys and values are represented
/// by 4 field elements.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Smt {
    root: RpoDigest,
    // pub(super) for use in PartialSmt.
    pub(super) leaves: Leaves,
    inner_nodes: InnerNodes,
}

impl Smt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Smt].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        Self {
            root,
            inner_nodes: Default::default(),
            leaves: Default::default(),
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        #[cfg(feature = "concurrent")]
        {
            Self::with_entries_concurrent(entries)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            Self::with_entries_sequential(entries)
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// This sequential implementation processes entries one at a time to build the tree.
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    #[cfg(any(not(feature = "concurrent"), fuzzing, test))]
    fn with_entries_sequential(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        use alloc::collections::BTreeSet;

        // create an empty tree
        let mut tree = Self::new();

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (key, value) in entries {
            let old_value = tree.insert(key, value);

            if old_value != EMPTY_WORD || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(
                    LeafIndex::<SMT_DEPTH>::from(key).value(),
                ));
            }

            if value == EMPTY_WORD {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    /// Returns a new [`Smt`] instantiated from already computed leaves and nodes.
    ///
    /// This function performs minimal consistency checking. It is the caller's responsibility to
    /// ensure the passed arguments are correct and consistent with each other.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if `root` does not match the root node in
    /// `inner_nodes`.
    pub fn from_raw_parts(inner_nodes: InnerNodes, leaves: Leaves, root: RpoDigest) -> Self {
        // Our particular implementation of `from_raw_parts()` never returns `Err`.
        <Self as SparseMerkleTree<SMT_DEPTH>>::from_raw_parts(inner_nodes, leaves, root).unwrap()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> RpoDigest {
        <Self as SparseMerkleTree<SMT_DEPTH>>::root(self)
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    pub fn num_entries(&self) -> usize {
        self.entries().count()
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &RpoDigest) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &RpoDigest) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &RpoDigest) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.leaves.is_empty(), self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    pub fn entries(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`Smt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{hash::rpo::RpoDigest, Felt, Word};
    /// # use miden_crypto::merkle::{Smt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt = Smt::new();
    /// let pair = (RpoDigest::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]);
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
        #[cfg(feature = "concurrent")]
        {
            self.compute_mutations_concurrent(kv_pairs)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
        }
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<(), MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations(self, mutations)
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, RpoDigest, Word>, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations_with_reversion(self, mutations)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        match self.leaves.get_mut(&leaf_index.value()) {
            Some(leaf) => leaf.insert(key, value),
            None => {
                self.leaves.insert(leaf_index.value(), SmtLeaf::Single((key, value)));

                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        if let Some(leaf) = self.leaves.get_mut(&leaf_index.value()) {
            let (old_value, is_empty) = leaf.remove(key);
            if is_empty {
                self.leaves.remove(&leaf_index.value());
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }
}

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: RpoDigest = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        inner_nodes: InnerNodes,
        leaves: Leaves,
        root: RpoDigest,
    ) -> Result<Self, MerkleError> {
        if cfg!(debug_assertions) {
            let root_node = inner_nodes.get(&NodeIndex::root()).unwrap();
            assert_eq!(root_node.hash(), root);
        }

        Ok(Self { root, inner_nodes, leaves })
    }

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes
            .get(&index)
            .cloned()
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        self.inner_nodes.insert(index, inner_node)
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.remove(&index)
    }

    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        if value != Self::EMPTY_VALUE {
            self.perform_insert(key, value)
        } else {
            self.perform_remove(key)
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.get_value(key).unwrap_or_default(),
            None => EMPTY_WORD,
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => SmtLeaf::new_empty(key.into()),
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        mut existing_leaf: SmtLeaf,
        key: &RpoDigest,
        value: &Word,
    ) -> SmtLeaf {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => SmtLeaf::new_single(*key, *value),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value);
                } else {
                    existing_leaf.remove(*key);
                }

                existing_leaf
            },
        }
    }

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Word> for LeafIndex<SMT_DEPTH> {
    fn from(value: Word) -> Self {
        // We use the most significant `Felt` of a `Word` as the leaf index.
        Self::new_max_depth(value[3].as_int())
    }
}

impl From<RpoDigest> for LeafIndex<SMT_DEPTH> {
    fn from(value: RpoDigest) -> Self {
        Word::from(value).into()
    }
}

impl From<&RpoDigest> for LeafIndex<SMT_DEPTH> {
    fn from(value: &RpoDigest) -> Self {
        Word::from(value).into()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Smt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of filled leaves for this Smt
        target.write_usize(self.entries().count());

        // Write each (key, value) pair
        for (key, value) in self.entries() {
            target.write(key);
            target.write(value);
        }
    }

    fn get_size_hint(&self) -> usize {
        let entries_count = self.entries().count();

        // Each entry is the size of a digest plus a word.
        entries_count.get_size_hint()
            + entries_count * (RpoDigest::SERIALIZED_SIZE + EMPTY_WORD.get_size_hint())
    }
}

impl Deserializable for Smt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read the number of filled leaves for this Smt
        let num_filled_leaves = source.read_usize()?;
        let mut entries = Vec::with_capacity(num_filled_leaves);

        for _ in 0..num_filled_leaves {
            let key = source.read()?;
            let value = source.read()?;
            entries.push((key, value));
        }

        Self::with_entries(entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// FUZZING
// ================================================================================================

#[cfg(fuzzing)]
impl Smt {
    pub fn fuzz_with_entries_sequential(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Smt, MerkleError> {
        Self::with_entries_sequential(entries)
    }

    pub fn fuzz_compute_mutations_sequential(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
    }
}

// TESTS
// ================================================================================================

#[test]
fn test_smt_serialization_deserialization() {
    // Smt for default types (empty map)
    let smt_default = Smt::default();
    let bytes = smt_default.to_bytes();
    assert_eq!(smt_default, Smt::read_from_bytes(&bytes).unwrap());
    assert_eq!(bytes.len(), smt_default.get_size_hint());

    // Smt with values
    let smt_leaves_2: [(RpoDigest, Word); 2] = [
        (
            RpoDigest::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
            [Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)],
        ),
        (
            RpoDigest::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
            [Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)],
        ),
    ];
    let smt = Smt::with_entries(smt_leaves_2).unwrap();

    let bytes = smt.to_bytes();
    assert_eq!(smt, Smt::read_from_bytes(&bytes).unwrap());
    assert_eq!(bytes.len(), smt.get_size_hint());
}
