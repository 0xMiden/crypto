//! A high-performance sparse merkle tree forest backed by pluggable storage.

mod error;
mod history;

pub use error::LargeSmtForestError;
pub use history::{History, HistoryView, error::HistoryError};
