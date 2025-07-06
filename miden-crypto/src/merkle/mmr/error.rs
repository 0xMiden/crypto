use alloc::string::String;

use thiserror::Error;

use crate::merkle::MerkleError;

#[derive(Debug, Error)]
/// Errors that can occur during operations on a Merkle Mountain Range (MMR).
pub enum MmrError {
    #[error("mmr does not contain position {0}")]
    /// Indicates that the requested position does not exist in the MMR.
    PositionNotFound(usize),
    #[error("mmr peaks are invalid: {0}")]
    /// Indicates that the provided MMR peaks are malformed or invalid.
    InvalidPeaks(String),
    #[error("mmr peak does not match the computed merkle root of the provided authentication path")]
    /// A peak's authentication path does not match its expected Merkle root.
    PeakPathMismatch,
    #[error("requested peak index is {peak_idx} but the number of peaks is {peaks_len}")]
    /// Indicates that the requested peak index is out of bounds.
    PeakOutOfBounds { peak_idx: usize, peaks_len: usize },
    #[error("invalid mmr update")]
    /// An attempted update to the MMR was invalid or unsupported.
    InvalidUpdate,
    #[error("mmr does not contain a peak with depth {0}")]
    /// The MMR does not contain a peak with the specified depth.
    UnknownPeak(u8),
    #[error("invalid merkle path")]
    /// The provided Merkle path is invalid.
    InvalidMerklePath(#[source] MerkleError),
    #[error("merkle root computation failed")]
    /// The Merkle root could not be computed from the given data.
    MerkleRootComputationFailed(#[source] MerkleError),
}
