//! A high-performance sparse merkle tree forest backed by pluggable storage.
//!
//! # Semantic Layout
//!
//! Much like `SparseMerkleTree`, the forest stores trees of depth 64 that use the compact leaf
//! optimization to uniquely store 256-bit elements. This reduces both the size of a merkle path,
//! and the computational work necessary to perform queries into the trees.
//!
//! # Storing Trees and Versions
//!
//! The usage of an SMT forest is conceptually split into two parts: a collection that is able to
//! store **multiple, unrelated trees**, and a container for **multiple versions of those trees**.
//! Both of these use-cases are supported by the forest, but have an explicit delineation between
//! them in both the API and the implementation. This has two impacts that a client of the forest
//! must understand.
//!
//! - While, when using a [`Storage`] that can persist data, **only the current full tree state is
//!   persisted**, while **the historical data will not be**. This is designed into the structure of
//!   the forest, and does not depend on the choice of storage backend.
//! - It is more expensive to query a given tree at an older point in its history than it is to
//!   query it at a newer point, and querying at the current tree will always take the least time.
//!
//! # Data Storage
//!
//! In order to help with the query performance for the more latency-prone kinds of [`Storage`]
//! implementation, the forest splits the data into two portions:
//!
//! 1. The **top of each tree** is explicitly **stored in memory**, regardless of the [`Storage`]
//!    backend. This makes the common tree prefix much more performant to query, and relies on the
//!    backend to store sufficient data to _reconstruct_ that prefix at forest rebuild.
//! 2. The **rest of each tree** is managed by the [`Storage`] itself, and makes no guarantees as to
//!    where that data is stored. Queries into this portion have performance characteristics
//!    dictated by the choice of storage backend.
//!
//! The split between these numbers of levels is configured when initially constructing the forest,
//! and will be verified at runtime for forests that are instead reloaded from persistent state.

mod error;
pub mod history;
pub mod storage;
pub mod utils;

pub use error::LargeSmtForestError;
pub use storage::{Storage, StorageError, StoredTreeHandle};
pub use utils::SubtreeLevels;
