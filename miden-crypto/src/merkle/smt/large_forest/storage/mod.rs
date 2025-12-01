//! This module contains the definition of [`Storage`], the backing data store for the SMT forest.
//!
//! The forest itself is designed to be storage agnostic, and provides the minimum set of operations
//! for reading and writing to the storage backend. It is intended that very little logic should
//! reside in the storage itself. The primary documentation for those both using and implementing
//! the traits in this module can be found on [`Storage`] and [`StoredTreeHandle`] themselves.
//!
//! # Performance
//!
//! Having an arbitrary `S: Storage` does not give you any performance guarantees about the forest
//! itself. To that end, reasoning about performance should always be done in the context of a
//! concrete instance of the storage. Please see specific implementations for details about
//! performance.

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;

pub mod error;

pub use error::{Result, StorageError};

use crate::{
    Word,
    merkle::{
        NodeIndex,
        smt::{InnerNode, SmtLeaf, large_forest::utils::SubtreeLevels},
    },
};

/// A **temporary** stand-in for the subtree type that will come in a subsequent PR.
pub type Subtree = ();

// STORAGE TRAIT
// ================================================================================================

/// The backing storage for the large SMT forest, providing the necessary methods for reading
/// from and writing to an arbitrary storage structure while allowing the forest itself to be
/// storage agnostic.
///
/// # Storage Structure
///
/// The forest's data is physically split into two parts, though this division should not be visible
/// to clients of the forest.
///
/// 1. **Guaranteed In Memory:** This portion of the forest, consisting of some number of levels
///    from the top of each stored tree is guaranteed to reside in memory.
/// 2. **Arbitrary Storage:** The remainder of the forest's data is stored in a place that makes no
///    guarantees as to where it is stored (e.g. in memory, on disk, and so on).
///
/// An implementation of [`Storage`] is responsible for managing the latter part, and has no
/// information about the portion of the data guaranteed to reside in memory. Merging the data from
/// the two to create a coherent forest is the responsibility of the forest implementation itself.
///
/// **Note that** the forest may choose to retain **no portion of the node data** as guaranteed to
/// be in memory. This means that storage implementations must be **agnostic** to the portion of the
/// tree that they store. At a minimum they could store the leaves, and at the maximum they could
/// store the entire tree, though with many storage backends this may incur significant performance
/// cost.
///
/// # Transactions
///
/// Many implementations of [`Storage`] will need to use transaction-based operations to ensure
/// consistency for the data in the case of crashes. To that end, the trait provides functionality
/// for working with transactions as follows:
///
/// 1. Request a transaction to start by calling [`Storage::begin`].
/// 2. Perform any number of operations on the individual persisted tree states in the forest by
///    using [`Storage::tree`] as an interface to do so.
/// 3. Request that the transaction end by calling [`Storage::commit`].
///
/// While this workflow is an inherent part of the trait, not all backends will support the use of
/// transactions. A purely in-memory backend, for example, will likely perform its reads and writes
/// eagerly. This means that a client of a [`Storage`] implementation, namely the SMT forest, **must
/// not make assumptions** about **_when_ and _in what order_ data is written to disk**.
///
/// - It is recommended that any **storage that does support transactions** guard operations on
///   there being an active transaction. Not doing so risks subtle, programmer-induced data
///   corruption.
/// - For **storage that does not support transactions**, it is recommended to set
///   `TransactionHandle = ()` to indicate this. Nevertheless, it must support calling
///   [`Storage::begin`] and [`Storage::commit`] without raising an error so the forest can be
///   properly storage agnostic.
///
/// This ensures that the forest that uses the storage can assume the existence of transactions and
/// use them properly, regardless of the actual transaction support in a given backend. If they are
/// supported they will be used, and if they are not there is no harm done with a nop call.
///
/// # Interior Mutability
///
/// This trait is designed to take advantage of the _interior mutability_ pattern, allowing anybody
/// with a standard reference to the storage to mutate it. This is to support a reasonable interface
/// that can be employed from parallel contexts, while also supporting a wide array of potential
/// concrete storage implementations.
///
/// As a result, **care must be taken** to ensure the correctness of any given storage
/// implementation, as the type system is less able to assist the programmer with its correctness.
///
/// # Errors
///
/// All methods are intended to handle potential storage errors by returning the trait's [`Result`]
/// type. Suggested errors are documented for each method, but these may be changed by any concrete
/// implementation of the trait.
pub trait Storage
where
    Self: Debug + Send + Sync + 'static,
{
    /// The type of the handle used to identify transactions in the storage.
    ///
    /// The handle type may be set to `()` to indicate that the particular backend does not support
    /// transactions. Such backends may mutate their stored data eagerly instead.
    type TransactionHandle;

    /// The type of handles to the data associated with a **specific tree** in the storage.
    type TreeDataHandle: StoredTreeHandle;

    /// Returns the number of levels in each tree that are guaranteed to be stored in memory, and
    /// hence that are **not managed by the storage** itself, in order to ensure correct
    /// forest-state restoration in persistent storage scenarios.
    ///
    /// Please see the documentation of [`SubtreeLevels`] for the exact way these are counted.
    fn in_memory_depth(&self) -> Result<SubtreeLevels>;

    /// Returns the number of unique trees that have had data stored within the storage.
    fn tree_count(&self) -> Result<usize>;

    /// Returns the roots for all the trees that have data stored in the forest.
    fn roots(&self) -> Result<Vec<Word>>;

    /// Begins a new transaction, returning a handle to it.
    ///
    /// **Not all storage backends may support a notion of transactions**. In such cases this may
    /// be a no-op, and it is recommended to set `TransactionHandle = ()` to indicate this. Such
    /// backends will mutate data eagerly, but still must allow [`Storage::begin`] to succeed.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while trying to begin a transaction.
    /// - [`StorageError::MultipleTransactionsUnsupported`] if the backend does not support multiple
    ///   concurrent transactions.
    fn begin(&self) -> Result<Self::TransactionHandle>;

    /// Ends the transaction described by `handle`, making all staged writes to the storage concrete
    /// and durable.
    ///
    /// **Not all storage backends may support a notion of atomic writes**. In such cases this may
    /// be a no-op, and it is recommended to set `TransactionHandle = ()` to indicate this. Such
    /// backends will mutate data eagerly, but still must allow [`Storage::begin`] to succeed.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while trying to commit a transaction.
    /// - [`StorageError::UnknownTransaction`] if the backend is passed a transaction handle that it
    ///   did not allocate to the caller.
    fn commit(&self, handle: Self::TransactionHandle) -> Result<()>;

    /// Gets a handle to the storage as if it only consists of the data for the tree with the
    /// provided `root`.
    ///
    /// It is intended that all manipulation of a given tree in storage takes place via the returned
    /// [`Self::TreeDataHandle`], and as such there are no manipulation operations exposed directly
    /// on the storage. This improves the ergonomics of working with the data of multiple trees in
    /// the forest at once.
    ///
    /// Multiple of these handles must be able to be held and used at once by the caller of the
    /// `Storage`, as this is the explicitly-intended use-case.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while trying to query for such a tree.
    /// - [`StorageError::NotInTransaction`] if the backend supports transactions and this operation
    ///   is called while no transaction is active.
    /// - [`StorageError::UnknownRoot`] if no tree with the provided `root` exists in the storage.
    fn tree(&self, root: Word) -> Result<Self::TreeDataHandle>;
}

// TREE VIEW TRAIT
// ================================================================================================

/// A handle to the data for the specified tree in the storage.
///
/// This handle **does not provide access to an entire tree**, but instead only grants access to
/// the **portion of the tree managed by the storage** (see the [`Storage`] documentation for more
/// detail). It primarily exists for the purpose of ergonomics, as it avoids the need to identify
/// the intended tree in every operation.
///
/// # Reading and Writing
///
/// Read and write operations via this view are **not guaranteed to be synchronous**. Write
/// operations in particular may be deferred (e.g. to ensure on-disk consistency in case of a
/// crash). This means that some errors may appear to be decoupled from the actions that actually
/// caused them.
///
/// # Interior Mutability
///
/// This trait is designed to take advantage of the _interior mutability_ pattern, allowing anybody
/// with a standard reference to the storage to mutate it. This is to support a reasonable interface
/// that can be employed from parallel contexts, while also supporting a wide array of potential
/// concrete storage implementations.
///
/// As a result, **care must be taken** to ensure the correctness of the storage implementation, as
/// the type system is less able to assist the programmer in its implementation.
///
/// # Errors
///
/// All methods are intended to handle potential storage errors by returning the trait's [`Result`]
/// type. Suggested errors are documented for each method, but these may be changed by any concrete
/// implementation of the trait.
pub trait StoredTreeHandle
where
    Self: Debug + Send + Sync + 'static,
{
    /// Gets the stored root of the tree whose data this handle points to.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while trying to read the root.
    fn root(&self) -> Result<Word>;

    /// Sets the stored root for the tree in question to the provided `root`.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while trying update the root.
    fn set_root(&self, root: Word) -> Result<Word>;

    /// Gets the number of leaves that are _currently stored_ for this tree.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while reading the leaf count.
    fn leaf_count(&self) -> Result<usize>;

    /// Sets the number of leaves that are _currently stored_ for this tree.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while reading the leaf count.
    fn set_leaf_count(&self, leaf_count: usize) -> Result<()>;

    /// Gets the number of **unique entries** that are currently stored across all leaf nodes for
    /// this tree.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while reading the leaf count.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn entry_count(&self) -> Result<Word>;

    /// Sets the number of **unique entries** that are currently stored across all leaf nodes for
    /// this tree.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while reading the leaf count.
    fn set_entry_count(&self, entry: Word) -> Result<()>;

    /// Inserts the provided `value` under the given `key` into the tree, returning the previous
    /// value for that key or [`None`] otherwise.
    ///
    /// - If the corresponding leaf does not exist, this method may create it.
    /// - If the `key` exists in the leaf, its value is updated.
    ///
    /// This method **does not** handle propagating the changes that result from making the
    /// insertion into the leaf. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn insert_value(&self, key: Word, value: Word) -> Result<Option<Word>>;

    /// Gets the value associated with the provided `key`, or returns [`None`] if no such value
    /// exists.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn get_value(&self, key: Word) -> Result<Option<Word>>;

    /// Removes the key-value pair denoted by the provided `key` from the tree, returning the value
    /// if it existed or [`None`] otherwise.
    ///
    /// If removing the entry causes the leaf to become empty, the behavior of the leaf node itself
    /// (e.g. becoming sparse again or not) is implementation dependent.
    ///
    /// This method **does not** handle propagating the changes that result from making the removal
    /// from the leaf. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn remove_value(&self, key: Word) -> Result<Option<Word>>;

    /// Returns `true` if the storage has any non-sparse leaves, and `false` otherwise.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    fn has_leaves(&self) -> Result<bool>;

    /// Retrieves a single compact SMT leaf node from its logical index, returning the leaf if it
    /// exists or [`None`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>>;

    /// Sets the leaf at the provided logical `index` to the value of `leaf`, returning the prior
    /// leaf if one was replaced or [`None`] otherwise.
    ///
    /// This method **does not** handle propagating the changes that result from making the leaf
    /// alteration. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn set_leaf(&self, index: u64, leaf: SmtLeaf) -> Result<Option<SmtLeaf>>;

    /// Removes the leaf at the provided logical `index` from storage, returning the leaf if it
    /// existed, or [`None`] otherwise.
    ///
    /// The implementation is required to replace the removed leaf with a sparse leaf entry, rather
    /// than an empty but extant leaf value.
    ///
    /// This method **does not** handle propagating the changes that result from removing the leaf.
    /// This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaf.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>>;

    /// Gets the leaves at the specified logical `indices`, returning them in the same order, or
    /// returning [`None`] for any missing leaves.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaves.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>>;

    /// Sets the leaves at the given indices to the given values, replacing any existing leaves at
    /// those indices and returning the prior one, or returning [`None`] otherwise.
    ///
    /// This method **does not** handle propagating the changes that result from editing these
    /// leaves. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaves.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn set_leaves(&self, leaves: Vec<(u64, SmtLeaf)>) -> Result<Vec<Option<SmtLeaf>>>;

    /// Removes the leaves at the specified logical `indices`, returning (for each index) the leaf
    /// if it existed or [`None`] otherwise.
    ///
    /// The implementation is required to replace each removed leaf with a sparse leaf entry, rather
    /// than an empty but extant leaf value.
    ///
    /// This method **does not** handle propagating the changes that result from removing these
    /// leaves. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the leaves.
    /// - [`StorageError::Leaf`] if a malformed leaf is found during the query.
    fn remove_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>>;

    /// Gets the subtree with the provided `index` for its root, or returns [`None`] if no such
    /// subtree can be found.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtree.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>>;

    /// Sets the value of the subtree with the provided `index` for its root to `subtree`, returning
    /// any previous tree at that index or [`None`] if there was none.
    ///
    /// This method **does not** handle propagating the changes that result from editing the
    /// subtree. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtree.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn set_subtree(&self, index: NodeIndex, subtree: Subtree) -> Result<Option<Subtree>>;

    /// Removes the subtree with the provided `index` for its root, returning it if it existed or
    /// [`None`] otherwise.
    ///
    /// The implementation is required to replace each removed subtree with a sparse subtree entry,
    /// rather than a dense but defaulted subtree.
    ///
    /// This method **does not** handle propagating the changes that result from removing the
    /// subtree. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtree.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn remove_subtree(&self, index: &NodeIndex) -> Result<Option<Subtree>>;

    /// Gets the subtrees at the provided `indices` for their roots, or returns [`None`] should any
    /// of those indices not contain a tree.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtrees.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>>;

    /// Sets the value for each subtree with root at the index to the corresponding tree value,
    /// returning the previous value if it existed or [`None`] if it did not.
    ///
    /// This method **does not** handle propagating the changes that result from editing the
    /// subtree. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtrees.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn set_subtrees(&self, subtrees: Vec<(NodeIndex, Subtree)>) -> Result<Vec<Option<Subtree>>>;

    /// Removes the subtrees with the provided root `indices`, returning those that existed and
    /// returning [`None`] for those that did not.
    ///
    /// The implementation is required to replace each removed subtree with a sparse subtree entry,
    /// rather than a dense but defaulted subtree.
    ///
    /// This method **does not** handle propagating the changes that result from editing the
    /// subtree. This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while operating on the subtrees.
    /// - [`StorageError::Subtree`] if a malformed subtree is found during the query.
    /// - [`StorageError::NotInStorage`] if the storage is queried for a subtree that is in the
    ///   guaranteed-to-be-in-memory portion of the tree.
    fn remove_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>>;

    /// Gets the node of the tree at the specified `index`, or returns [`None`] if the node is
    /// sparse.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying the node.
    /// - [`StorageError::NotInStorage`] if the node at the provided `index` is not in the storage
    ///   (e.g. due to being in the in-memory portion of the tree).
    fn get_node(&self, index: NodeIndex) -> Result<Option<InnerNode>>;

    /// Sets the node value at the provided `index` to the `node`, returning the previous value if
    /// it existed or [`None`] otherwise.
    ///
    /// This method **does not** handle propagating the changes that result from editing the node.
    /// This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying the node.
    /// - [`StorageError::NotInStorage`] if the node at the provided `index` is not in the storage
    ///   (e.g. due to being in the in-memory portion of the tree).
    fn set_node(&self, index: NodeIndex, node: InnerNode) -> Result<Option<InnerNode>>;

    /// Removes the node at the provided `index`, returning it if it existed or [`None`] if it did
    /// not.
    ///
    /// The implementation is required to make the storage for the removed node _sparse_, rather
    /// than replace it with a defaulted but present entry.
    ///
    /// This method **does not** handle propagating the changes that result from removing the node.
    /// This is the responsibility of the caller.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying the node.
    /// - [`StorageError::NotInStorage`] if the node at the provided `index` is not in the storage
    ///   (e.g. due to being in the in-memory portion of the tree).
    fn remove_node(&self, index: NodeIndex) -> Result<Option<InnerNode>>;

    /// Returns an iterator over all pairs of `(logical_index, leaf_value)` currently in the
    /// storage.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying.
    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>>;

    /// Returns an iterator over all _populated_ pairs of `(node_index, node_value)` for non-leaf
    /// nodes currently in the storage.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying.
    fn iter_nodes(&self) -> Result<Box<dyn Iterator<Item = (NodeIndex, Word)> + '_>>;

    /// Returns an iterator over all (semi)-_populated_ pairs of `(tree_root_index, subtree_val)`
    /// currently in the storage.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying.
    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = (NodeIndex, Subtree)> + '_>>;

    /// Returns the restoration data for the guaranteed-in-memory portion of the tree, consisting of
    /// a pair of `(num_levels, node_values)`.
    ///
    /// Each value in `node_values` is the cached root of a tree at the first level not guaranteed
    /// to be in memory, and will be in the order of those roots by index. If level `l` is the first
    /// level not guaranteed to be in memory, the result vector will contain `2^l` entries. These
    /// entries are **never sparse**.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if a backend error occurs while querying.
    fn restoration_data(&self) -> Result<Vec<Word>>;
}
