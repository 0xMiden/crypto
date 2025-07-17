use super::{MerkleStore, Word};

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(test, derive(PartialOrd, Ord))]
pub struct InnerNodeInfo {
    pub value: Word,
    pub left: Word,
    pub right: Word,
}

/// Provides an iterator over the inner nodes of a structure.
pub trait InnerNodeIterable {
    /// Returns an iterator over the inner nodes by borrowing the structure.
    fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo>;
}

/// Produces a [`MerkleStore`] from a structure.
pub trait IntoMerkleStore {
    fn to_merkle_store(&self) -> MerkleStore;
}

impl<T: InnerNodeIterable> IntoMerkleStore for T {
    fn to_merkle_store(&self) -> MerkleStore {
        MerkleStore::from_inner_nodes(self.inner_nodes())
    }
}
