use thiserror::Error;

#[derive(Debug, Error)]
pub enum SubtreeError {
    #[error("invalid hash data length: expected {expected} bytes, found {found} bytes")]
    BadHashLen { expected: usize, found: usize },
    #[error("invalid left hash format at local index {index}")]
    BadLeft { index: usize },
    #[error("invalid right hash format at local index {index}")]
    BadRight { index: usize },
    #[error("extra hash data after bitmask-indicated entries")]
    ExtraData,
    #[error("{0} is an invalid number of levels for a subtree")]
    InvalidLevelCount(u8),
    #[error("missing left hash data at local index {index}")]
    MissingLeft { index: usize },
    #[error("missing right hash data at local index {index}")]
    MissingRight { index: usize },
    #[error("subtree data too short: found {found} bytes, need at least {min} bytes")]
    TooShort { found: usize, min: usize },
}
