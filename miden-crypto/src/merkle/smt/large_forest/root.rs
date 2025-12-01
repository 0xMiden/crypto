//! This module contains utility types for working with roots as part of the forest.

/// Information about the role that a queried root plays in the forest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RootInfo {
    /// The queried root corresponds to a tree that is the latest version of a given tree in the
    /// forest.
    LatestVersion,

    /// The queried root corresponds to a tree that is _not_ the latest version of a given tree in
    /// the forest.
    HistoricalVersion,

    /// The queried root corresponds to the empty tree.
    EmptyTree,

    /// The queried root does not belong to any tree that the forest knows about.
    Missing,
}
