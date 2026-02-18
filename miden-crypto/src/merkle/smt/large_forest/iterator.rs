//! This module contains the implementation of the iterator over the entries of an arbitrary tree in
//! the forest.
//!
//! # Performance
//!
//! The performance of this iterator has a significant dependency on the tree that it is running
//! over. Due to the differing performance characteristics of backends, we cannot provide exact
//! performance bounds, but the following general rules apply.
//!
//! - Iterating over the entries of the **latest tree in a lineage** is going to be **the fastest
//!   possible query**. This depends only on the direct iteration performance of the backend in
//!   question.
//! - Iterating over the entries of **a historical tree is going to be slower**. This is because it
//!   has to do work to merge the entries provided by the history with the entries of the full tree
//!   in order to create a coherent picture of the historical tree.
//!
//! We highly recommend benchmarking the iteration behavior on the concrete workload(s) you are
//! concerned about, rather than trying to statically reason about performance of this iterator.

use alloc::boxed::Box;
use core::iter::Peekable;

use crate::{
    EMPTY_WORD,
    merkle::smt::{LeafIndex, large_forest::root::TreeEntry},
};

// ENTRIES ITERATOR
// ================================================================================================

/// An iterator over the entries of an arbitrary tree in the forest, yielding entries in an
/// arbitrary order.
///
/// It is split into two variants for performance, as iterating over a full tree is significantly
/// simpler than iterating over a historical tree. While it would be nice to be able to return one
/// of two different iterators depending on the circumstances of construction, Rust's `impl Trait`
/// bounds do not allow for this.
///
/// The iterator **must never transition between variants** during the process of iteration.
pub(super) enum EntriesIterator<'forest> {
    /// An iterator over a tree in the forest that is formed from a merger of the full tree and a
    /// historical overlay.
    WithHistory {
        /// The iterator over the entries in the full tree.
        ///
        /// This iterator should never yield any entries where `value == EMPTY_WORD`.
        full_tree_iter: Peekable<Box<dyn Iterator<Item = TreeEntry> + 'forest>>,

        /// The iterator over the entries in the history.
        ///
        /// This iterator may yield entries with `value == EMPTY_WORD`. These are explicit
        /// reversions of entries newly-set in newer versions, and so should be used. While they
        /// technically should only ever correspond to a case where they _are_ reverting a
        /// newly-set entry, care must be taken to remove them regardless if they do not match up
        /// for some reason.
        history_entries_iter: Peekable<Box<dyn Iterator<Item = TreeEntry> + 'forest>>,

        /// The current state of the iteration state machine.
        state: EntriesIteratorState,
    },

    /// An iterator over a tree in the forest that is simply an iterator over the full tree.
    WithoutHistory {
        /// The iterator over the entries in the full tree.
        full_tree_iter: Box<dyn Iterator<Item = TreeEntry> + 'forest>,
    },
}

impl<'forest> EntriesIterator<'forest> {
    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest`, formed by combining a historical overlay with the current tree.
    ///
    /// Note that it _does not_ perform checks as to the correctness of the provided iterators. If
    /// these are not an iterator over the full tree and the historical entries in turn, the results
    /// the iterator yields will be invalid.
    pub(super) fn new_with_history(
        full_tree_iter: impl Iterator<Item = TreeEntry> + 'forest,
        history_entries_iter: impl Iterator<Item = TreeEntry> + 'forest,
    ) -> Self {
        // This type gymnastics is unfortunately necessary to let us easily store the `Peekable`
        // which we need to avoid carrying additional state in the state machine.
        let full_tree_iter: Box<dyn Iterator<Item = _>> = Box::new(full_tree_iter);
        let history_entries_iter: Box<dyn Iterator<Item = _>> = Box::new(history_entries_iter);

        // We begin in `NotInLeaf`. This is implicitly `Start -> NotInLeaf`
        Self::WithHistory {
            full_tree_iter: full_tree_iter.peekable(),
            history_entries_iter: history_entries_iter.peekable(),
            state: EntriesIteratorState::NotInLeaf,
        }
    }

    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest` without any associated history.
    ///
    /// Note that it _does not_ check whether `full_tree_iter` is actually an iterator over the
    /// full tree. If it is not, the iterator will yield invalid results.
    pub(super) fn new_without_history(
        full_tree_iter: impl Iterator<Item = TreeEntry> + 'forest,
    ) -> Self {
        let full_tree_iter = Box::new(full_tree_iter);
        Self::WithoutHistory { full_tree_iter }
    }

    /// Advances the iterator and returns the next value in the case where it is iterating over a
    /// historical tree version.
    ///
    /// For the details of the state machine that this implements, please see the documentation for
    /// the [`EntriesIteratorState`]. It explains the valid state transitions and the conditions
    /// under which they occur. This implementation does not match them directly in order to
    /// simplify the logic, but matches the intended semantics.
    ///
    /// # Panics
    ///
    /// - If the method is called with a `self` that is not in the [`Self::WithHistory`] variant.
    #[inline(always)] // To help the optimizer eliminate the redundant check in Iterator::next()
    fn next_with_history(&mut self) -> Option<TreeEntry> {
        let EntriesIterator::WithHistory {
            full_tree_iter,
            history_entries_iter,
            state,
        } = self
        else {
            panic!("EntriesIterator::next_with_history called without history")
        };

        match state {
            EntriesIteratorState::NotInLeaf => {
                // Here we are (semantically) not pointing to any specific leaf, so we need to work
                // out which of our possible outgoing transitions take place. This state does not
                // actually return anything except in the `-> End` case.
                match (full_tree_iter.peek(), history_entries_iter.peek()) {
                    (None, None) => {
                        // No more entries exist in either of the iterators. `NotInLeaf -> End`.
                        None
                    },
                    (Some(_), None) => {
                        // Entries only exist in the full tree iterator. `NotInLeaf -> TreeOnly`
                        *state = EntriesIteratorState::TreeOnly;
                        self.next_with_history()
                    },
                    (None, Some(_)) => {
                        // Entries only exist in the full tree iterator. `NotInLeaf -> HistOnly`
                        *state = EntriesIteratorState::HistOnly;
                        self.next_with_history()
                    },
                    (Some(full), Some(hist)) => {
                        // Entries exist in both, but the exact state transition has not yet been
                        // determined. We have three other possible outgoing edges from `NotInLeaf`.
                        let full_idx = LeafIndex::from(full.key);
                        let hist_idx = LeafIndex::from(hist.key);

                        if full_idx == hist_idx {
                            // We are in the same leaf. `NotInLeaf -> InLeafShared`
                            *state = EntriesIteratorState::InLeafShared;
                        } else if full_idx < hist_idx {
                            // We are in different leaves with full_idx coming first. `NotInLeaf ->
                            // InLeafTreeOnly`
                            *state = EntriesIteratorState::InLeafTreeOnly;
                        } else {
                            // We are in different leaves with hist_idx coming first. `NotInLeaf ->
                            // InTreeHistOnly`.
                            *state = EntriesIteratorState::InLeafHistOnly;
                        }

                        self.next_with_history()
                    },
                }
            },
            EntriesIteratorState::HistOnly => {
                // In this state we simply can continue yielding the history entries iterator until
                // it is empty. We just have to check that we're not yielding EMPTY_WORD entries
                // directly as these should not be seen.
                history_entries_iter.next().and_then(|e| {
                    if e.value == EMPTY_WORD {
                        self.next_with_history()
                    } else {
                        Some(e)
                    }
                })
            },
            EntriesIteratorState::TreeOnly => {
                // In this state we can simply continue yielding the tree entries iterator until it
                // is empty. When it returns `None` we have `TreeOnly -> End`
                full_tree_iter.next()
            },
            EntriesIteratorState::InLeafHistOnly => {
                // Here, we are in a leaf that is only in the history. We technically only want to
                // transition out of this state once we have exhausted the leaf, but in actuality we
                // can rely on the logic for `NotInLeaf` to do the right thing here. We only have to
                // skip empty words as these should never be yielded.
                *state = EntriesIteratorState::NotInLeaf;
                history_entries_iter.next().and_then(|e| {
                    if e.value == EMPTY_WORD {
                        self.next_with_history()
                    } else {
                        Some(e)
                    }
                })
            },
            EntriesIteratorState::InLeafTreeOnly => {
                // Here we are in a leaf that is only in the full tree. We technically only want to
                // transition out of this state once we have exhausted the leaf, but in actuality we
                // can rely on the logic for `NotInleaf` to do the right thing here.
                *state = EntriesIteratorState::NotInLeaf;
                full_tree_iter.next()
            },
            EntriesIteratorState::InLeafShared => {
                // Here we have both iterators in the same LEAF but that does not mean they have the
                // same item.
                let hist_item =
                    history_entries_iter.peek().expect("Entry already checked to exist");
                let tree_item = full_tree_iter.peek().expect("Entry already checked to exist");

                if hist_item.key == tree_item.key {
                    *state = EntriesIteratorState::InLeafBothKeysEq;
                } else if hist_item.key < tree_item.key {
                    *state = EntriesIteratorState::InLeafBothHistPrio;
                } else {
                    *state = EntriesIteratorState::InLeafBothTreePrio;
                }

                self.next_with_history()
            },
            EntriesIteratorState::InLeafBothKeysEq => {
                // If the keys are equal we want to pop both entries and only return the history's
                // one. We can again rely on `NotInLeaf` to do our logic correctly.
                *state = EntriesIteratorState::NotInLeaf;

                // We can discard this entry entirely as it has been overwritten.
                full_tree_iter.next();

                // But this one may or may not need to be returned.
                let hist_item =
                    history_entries_iter.next().expect("Entry already checked to exist");
                if hist_item.value == EMPTY_WORD {
                    // We never want to yield empty items, so we skip them.
                    self.next_with_history()
                } else {
                    // Otherwise the item is real and we want to yield it.
                    Some(hist_item)
                }
            },
            EntriesIteratorState::InLeafBothHistPrio => {
                // Here we have a history item with a key < the full tree item, so we want to return
                // that. We can again rely on `NotInLeaf` to do our logic correctly.
                *state = EntriesIteratorState::NotInLeaf;
                history_entries_iter.next()
            },
            EntriesIteratorState::InLeafBothTreePrio => {
                // Here we have a full tree item with a key < the history item, so we want to return
                // that. We can again rely on `NotInLeaf` to do our logic correctly.
                *state = EntriesIteratorState::NotInLeaf;
                full_tree_iter.next()
            },
        }
    }

    /// Advances the iterator and returns the next value in the case where it is iterating over the
    /// current tree version.
    ///
    /// # Panics
    ///
    /// - If the method is called with a `self` that is not the [`Self::WithoutHistory`] variant.
    #[inline(always)] // To help the optimizer eliminate the redundant check in Iterator::next()
    fn next_without_history(&mut self) -> Option<TreeEntry> {
        let EntriesIterator::WithoutHistory { full_tree_iter } = self else {
            panic!("EntriesIterator::next_without_history called with history")
        };

        full_tree_iter.next()
    }
}

// ITERATOR TRAIT
// ================================================================================================

impl Iterator for EntriesIterator<'_> {
    type Item = TreeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntriesIterator::WithHistory { .. } => self.next_with_history(),
            EntriesIterator::WithoutHistory { .. } => self.next_without_history(),
        }
    }
}

// ENTRIES ITERATOR STATE
// ================================================================================================

/// The state machine that is the entries iterator for the forest.
///
/// We do not represent the ghost states of `Start` and `End`, so [`Self::NotInLeaf`] serves as the
/// initial state of the machine in practice. A full diagram of the state machine's allowable
/// transitions can be found below. See the individual variants for the conditions under which these
/// transitions take place.
///
/// ```text
///                                    ┌─────────┐
///                                    │  Start  │
///                                    └─────────┘
///                                         │
///                                         │
///                                         ▼
///                                   ┌───────────┐
///        ┌─────────────┬────────────│           │◀──────────────┬──────────────────┐
///        │             │            │ NotInLeaf │               │                  │
///        │             │       ┌────│           │────────────┬──┼───────────────┐  │
///        │             │       │    └───────────┘            │  │               │  │
///        │             │       │         │  ▲                │  │               │  │
///        │             │       │         │  │                │  │               │  │
///        │             │       │         │  │                │  │               │  │
///        │             │       │         │  │                │  │               │  │
///        ▼             ▼       │         ▼  │                ▼  │               ▼  │
///  ┌──────────┐  ┌──────────┐  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐
///  │ TreeOnly │  │ HistOnly │  │  │ InLeafHistOnly │  │ InLeafTreeOnly │  │ InLeafShared │◀─────────────┐
///  └──────────┘  └──────────┘  │  └────────────────┘  └────────────────┘  └──────────────┘              │
///        │             │       │                                                  │                     │
///        │             │       │                                                  │                     │
///        │             │       │            ┌──────────────────────┬──────────────┴────────┐            │
///        │             │       │            │                      │                       │            │
///        │             │       │            ▼                      ▼                       ▼            │
///        │             │       │  ┌──────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │
///        └─────────────┴─────┐ │  │ InLeafBothKeysEq │  │ InLeafBothHistPrio │  │ InLeafBothTreePrio │  │
///                            │ │  └──────────────────┘  └────────────────────┘  └────────────────────┘  │
///                            │ │            │                      │                       │            │
///                            │ │            │                      │                       │            │
///                            │ │            └──────────────────────┴───────────────────────┴────────────┘
///                            ▼ ▼
///                        ┌─────────┐
///                        │   End   │
///                        └─────────┘
/// ```
///
/// Note that this describes the _semantics_ of the transitions between states, and may not directly
/// correspond to the implementation in [`EntriesIterator::next_with_history`] for reasons of
/// performance and maintainability.
pub(super) enum EntriesIteratorState {
    /// The iterator is currently not in any leaf.
    ///
    /// This state should not advance the underlying iterators directly, and the iterator is not
    /// intended to return a value for `next` while in this state.
    ///
    /// Incoming state transitions:
    ///
    /// - `Start -> NotInLeaf`: The state of the state machine.
    /// - `InLeafHistOnly -> NotInLeaf`: Upon completing the leaf in the history.
    /// - `InLeafTreeOnly -> NotInLeaf`: Upon completing the leaf in the tree.
    /// - `InLeafShared -> NotInLeaf`: Upon completing the leaf that exists in both.
    ///
    /// Outgoing state transitions:
    ///
    /// - `NotInLeaf -> End`: If neither iterator has remaining entries.
    /// - `NotInLeaf -> HistOnly`: If the tree entries iterator is empty.
    /// - `NotInLeaf -> TreeOnly`: If the history entries iterator is empty.
    /// - `NotInLeaf -> InLeafHistOnly`: If the next leaf is only in the history.
    /// - `NotInLeaf -> InLeafTreeOnly`: If the next leaf is only in the tree.
    /// - `NotInLeaf -> InLeafShared`: If the leaf exists in both iterators.
    NotInLeaf,

    /// The iterator over the full tree has no entries, so we can iterate only over the history
    /// until completion.
    ///
    /// Incoming state transitions:
    ///
    /// - `NotInLeaf -> HistOnly`: The tree entries iterator is empty.
    ///
    /// Outgoing state transitions:
    ///
    /// - `HistOnly -> End`: The history entries iterator is empty.
    HistOnly,

    /// The iterator over the history has no entries, so we can iterate only over the full tree
    /// until completion.
    ///
    /// Incoming state transitions:
    ///
    /// - `NotInLeaf -> TreeOnly`: The history entries iterator is empty.
    ///
    /// Outgoing state transitions:
    ///
    /// - `TreeOnly -> End`: The tree entries iterator is empty.
    TreeOnly,

    /// The iterator is operating over a leaf that only exists in the history iterator.
    ///
    /// Incoming state transitions:
    ///
    /// - `NotInLeaf -> InLeafHistOnly`: The tree entries iterator has items but the latest is not
    ///   in the same leaf as the history's latest.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafHistOnly -> NotInLeaf`: Upon completing iteration through the current leaf.
    InLeafHistOnly,

    /// The iterator is operating over a leaf that only exists in the tree iterator.
    ///
    /// Incoming state transitions:
    ///
    /// - `NotInLeaf -> InLeafTreeOnly`: The history entries iterator has items but the latest is
    ///   not in the same leaf as the tree's latest.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafTreeOnly -> NotInLeaf`: Upon completing iteration through the current leaf.
    InLeafTreeOnly,

    /// The iterator is operating over a leaf that exists in both iterators.
    ///
    /// Incoming state transitions:
    ///
    /// - `NotInLeaf -> InLeafShared`: Both iterators have their latest entry in the same leaf.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafShared -> InLeafBothKeysEq`: If the two keys in the shared leaf are equal.
    /// - `InLeafShared -> InLeafBothKeysHistPrio`: If the key in the history < the key in the tree.
    /// - `InLeafShared -> InLeafBothKeysTreePrio`: If the key in the tree < the key in the history.
    /// - `InLeafShared -> NotInLeaf`: Upon completing iteration through the current leaf.
    InLeafShared,

    /// The iterator is operating over a leaf that exists in both iterators, and the current keys
    /// are the same.
    ///
    /// Incoming state transitions:
    ///
    /// - `InLeafShared -> InLeafBothKeysEq`: If the key in each iterator is the same.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafBothKeysEq -> InLeafShared`: When needing to check the next element.
    InLeafBothKeysEq,

    /// The iterator is operating over a leaf that exists in both iterators, and the current key
    /// in the history is less than the current key in the tree.
    ///
    /// Incoming state transitions:
    ///
    /// - `InLeafShared -> InLeafBothHistPrio`: If the key in the history iterator < the key in the
    ///   tree iterator.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafBothHistPrio -> InLeafShared`: When needing to check the next element.
    InLeafBothHistPrio,

    /// The iterator is operating over a leaf that exists in both iterators, and the current key in
    /// the tree is less than the current key in the history.
    ///
    /// Incoming state transitions:
    ///
    /// - `InLeafShared -> InLeafBothTreePrio`: If the key in the tree iterator < the key in the
    ///   history iterator.
    ///
    /// Outgoing state transitions:
    ///
    /// - `InLeafBothTreePrio -> InLeafShared`: When needing to check the next element.
    InLeafBothTreePrio,
}
