use super::Word;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(test, derive(PartialOrd, Ord))]
pub struct InnerNodeInfo {
    /// The value stored in this node a hash.
    pub value: Word,

    /// The left child node.
    pub left: Word,

    /// The right child node.
    pub right: Word,
}
