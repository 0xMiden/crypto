//! This module contains utility types for working with roots as part of the forest.

#[cfg(all(feature = "std", test))]
use crate::rand::test_utils::rand_value;
use crate::{Word, rand::Randomizable};

// TYPES
// ================================================================================================

/// An identifier for a lineage of trees.
///
/// This is an arbitrary, user-provided identifier that is used to disambiguate cases where trees in
/// distinct lineages are otherwise identical and have the same root.
pub type LineageId = [u8; 32];

// TODO LineageId?

// TODO Map lineage + version

/// A root for a tree in the forest.
pub type RootValue = Word;

/// An identifier for the version of a tree and hence a root.
pub type VersionId = u64;

// ROOT IDENTIFIER
// ================================================================================================

/// An identifier that is capable of uniquely referring to a root in the forest, even in the
/// presence of otherwise-identical trees.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Root {
    /// An identifier for the lineage in which the root may exist.
    lineage: LineageId,

    /// The root value of the tree in question.
    value: RootValue,
}

/// The base API for the `RootId`.
impl Root {
    /// Constructs a new root identifier for the provided `root` in the specified `lineage`.
    pub fn new(lineage: LineageId, value: RootValue) -> Self {
        Self { lineage, value }
    }

    /// Gets the lineage from the identifier.
    pub fn lineage(&self) -> LineageId {
        self.lineage
    }

    /// Gets the root value from the identifier.
    pub fn value(&self) -> RootValue {
        self.value
    }
}

/// Additional functionality for `RootId` for use during testing only.
#[cfg(test)]
impl Root {
    /// Generates a random root identifier.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        let domain = rand_value();
        let root = rand_value();
        Self::new(domain, root)
    }
}

impl Randomizable for LineageId {
    const VALUE_SIZE: usize = size_of::<LineageId>();

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let mut result = [0u8; Self::VALUE_SIZE];
        result.copy_from_slice(source);

        Some(result)
    }
}

// ROOT INFO
// ================================================================================================

/// Information about the role that a queried root plays in the forest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RootInfo {
    /// The queried root corresponds to a tree that is the latest version of a given tree in the
    /// forest.
    LatestVersion(VersionId),

    /// The queried root corresponds to a tree that is _not_ the latest version of a given tree in
    /// the forest.
    HistoricalVersion(VersionId),

    /// The queried root corresponds to the empty tree.
    EmptyTree,

    /// The queried root does not belong to any tree that the forest knows about.
    Missing,
}
