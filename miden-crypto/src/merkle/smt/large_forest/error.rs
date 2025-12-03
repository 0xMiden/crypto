//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use thiserror::Error;

use crate::merkle::{MerkleError, smt::history::error::HistoryError};

/// The errors returned by operations on the large SMT forest.
///
/// This type primarily serves to wrap more specific error types from various subsystems into a
/// generic interface type.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    #[error(transparent)]
    HistoryError(#[from] HistoryError),

    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

pub mod history {}
