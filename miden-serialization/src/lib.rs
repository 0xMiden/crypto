//! Serialization traits for Miden crypto primitives.
//!
//! This crate provides serialization and deserialization traits built on top of
//! the `embedded-io` ecosystem, supporting no_std environments.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// Module declarations - we'll create these in subsequent tasks
mod error;
mod byte_read;
mod byte_write;
// mod traits;
mod slice_reader;
// #[cfg(feature = "alloc")]
// mod vec_writer;
#[cfg(feature = "winterfell-compat")]
mod winterfell_bridge;

// Public exports
pub use error::DeserializationError;
pub use byte_read::ByteRead;
pub use byte_write::ByteWrite;
// pub use traits::{Serializable, Deserializable};
pub use slice_reader::SliceReader;

// #[cfg(feature = "alloc")]
// pub use vec_writer::VecWriter;

// #[cfg(feature = "std")]
// pub use embedded_io_adapters::blocking::{ReadAdapter as StdReadAdapter, WriteAdapter as StdWriteAdapter};

// Type aliases for hybrid approach (Option C from design)
/// Convenience type alias for serialization errors
pub type SerError = DeserializationError;
