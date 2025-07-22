use alloc::{boxed::Box, string::String};

use crate::utils::DeserializationError;

/// Errors returned by any `SmtStorage` implementation.
///
/// The enum is intentionally small – higher-level code should not need to know the
/// difference between, say, RocksDB and in-memory back-ends – but each variant
/// contains the original error so debugging information is not lost.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("backend error: {0}")]
    Backend(#[from] Box<dyn std::error::Error + Send + 'static>),
    #[error("deserialization failed: {0}")]
    Deserialize(#[from] DeserializationError),
    #[error("operation not supported: {0}")]
    Unsupported(String),
}
