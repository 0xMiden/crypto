//! This module contains utility types for working with roots as part of the forest.

use crate::Word;
#[cfg(all(feature = "std", test))]
use crate::rand::test_utils::rand_value;

// TYPES
// ================================================================================================

/// An identifier for the domain in which a lineage of trees exist.
///
/// A domain is an arbitrary, user-provided identifier that is used to disambiguate cases where
/// trees are otherwise identical and have the same root.
pub type DomainId = Word;

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
    /// An identifier for the domain in which the root may exist.
    domain: DomainId,

    /// The root value of the tree in question.
    value: RootValue,
}

/// The base API for the `RootId`.
impl Root {
    /// Constructs a new root identifier for the provided `root` in the specified `domain`.
    pub fn new(domain: DomainId, value: RootValue) -> Self {
        Self { domain, value }
    }

    /// Gets the domain from the identifier.
    pub fn domain(&self) -> DomainId {
        self.domain
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
