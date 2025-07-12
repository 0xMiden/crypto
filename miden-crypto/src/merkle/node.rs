use super::Word;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(test, derive(PartialOrd, Ord))]
pub struct InnerNodeInfo {
    pub value: Word,
    pub left: Word,
    pub right: Word,
}

/// A trait for structures that can provide an iterator over their inner nodes.
pub trait InnerNodeIterable {
    /// Returns an iterator over the inner nodes by borrowing the structure.
    fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo>;
}
