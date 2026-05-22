//! A compact rooted frontier for append-only Merkle trees.
//!
//! A [`MerkleFrontier`] stores the next leaf index (`len`) and the full left subtrees (`peaks`) on
//! the path to that next leaf. Empty right subtrees are implied, and the raw Merkle root is
//! obtained by folding this path. The authenticated frontier state is the pair `(len, root)`: the
//! root alone does not distinguish real leaves from implied empty padding.

use alloc::vec::Vec;

use super::{Forest, MmrError, MmrPeaks, MmrProof};
use crate::{
    Word,
    hash::poseidon2::Poseidon2,
    merkle::{EmptySubtreeRoots, MerkleError, MerklePath, MerkleProof},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// MERKLE FRONTIER
// ================================================================================================

/// A compact rooted frontier for an append-only Merkle tree.
///
/// The peaks are ordered from largest subtree to smallest subtree, matching [`MmrPeaks`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MerkleFrontier {
    /// The next leaf index in the append-only tree.
    len: usize,

    /// Full left subtrees on the path to `len`, ordered largest to smallest.
    peaks: Vec<Word>,
}

impl MerkleFrontier {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`MerkleFrontier`] instantiated from the specified length and peaks.
    ///
    /// # Errors
    /// Returns an error if the length exceeds the maximum supported forest size, or if the number
    /// of peaks does not match the number of full subtrees encoded by `len`.
    pub fn new(len: usize, peaks: Vec<Word>) -> Result<Self, MmrError> {
        validate_frontier(len, peaks.len())?;
        Ok(Self { len, peaks })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the next leaf index in the append-only tree.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if this frontier has no leaves.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of leaves currently committed by this frontier.
    pub fn num_leaves(&self) -> usize {
        self.len
    }

    /// Returns the number of peaks in this frontier.
    pub fn num_peaks(&self) -> usize {
        self.peaks.len()
    }

    /// Returns the peaks in largest-to-smallest order.
    pub fn peaks(&self) -> &[Word] {
        &self.peaks
    }

    /// Converts this frontier into its components.
    pub fn into_parts(self) -> (usize, Vec<Word>) {
        (self.len, self.peaks)
    }

    /// Converts this frontier into legacy [`MmrPeaks`] state.
    pub fn into_legacy_peaks(self) -> MmrPeaks {
        let forest = Forest::new(self.len).expect("frontier length must be valid");
        MmrPeaks::new(forest, self.peaks).expect("frontier peaks must be valid")
    }

    // FUNCTIONALITY
    // --------------------------------------------------------------------------------------------

    /// Returns the raw Merkle root of this frontier.
    ///
    /// The root is computed by folding the path to `len`: set bits consume peaks on the left and
    /// unset bits imply empty subtrees on the right. This root should be authenticated together
    /// with [`Self::len`]; by itself, it does not bind the number of real leaves before the implied
    /// empty padding.
    pub fn root(&self) -> Word {
        if self.len == 0 {
            return empty_subtree_root(0);
        }

        let mut bits = self.len;
        let mut level = 0u8;
        let mut peak_idx = self.peaks.len();
        let mut acc = empty_subtree_root(0);

        while bits != 0 {
            if bits & 1 == 1 {
                peak_idx -= 1;
                acc = Poseidon2::merge(&[self.peaks[peak_idx], acc]);
            } else {
                acc = Poseidon2::merge(&[acc, empty_subtree_root(level)]);
            }

            bits >>= 1;
            level += 1;
        }

        acc
    }

    /// Verifies a Merkle proof against this frontier.
    ///
    /// This treats the frontier's authenticated state as `(len, root)`: the position must be below
    /// [`Self::len`] before the proof is verified against [`Self::root`].
    pub fn verify(&self, position: usize, proof: &MerkleProof) -> Result<(), MmrError> {
        Self::verify_leaf(self.len, self.root(), position, proof.value, &proof.path)
    }

    /// Verifies a leaf opening against an authenticated `(len, root)` frontier pair.
    ///
    /// This is the safe public check to use when a verifier receives only the frontier length and
    /// raw root rather than the full [`MerkleFrontier`] state.
    pub fn verify_leaf(
        len: usize,
        root: Word,
        position: usize,
        leaf: Word,
        path: &MerklePath,
    ) -> Result<(), MmrError> {
        if !Forest::is_valid_size(len) {
            return Err(MmrError::ForestSizeExceeded { requested: len, max: Forest::MAX_LEAVES });
        }
        if position >= len {
            return Err(MmrError::PositionNotFound(position));
        }

        path.verify(position as u64, leaf, &root).map_err(MmrError::InvalidMerklePath)
    }

    /// Converts a peak-local MMR proof into a standard Merkle proof against this frontier's root.
    ///
    /// The input proof must be for the same forest length as this frontier. The returned path can
    /// be verified with [`Self::verify`] using the global leaf position. If only the frontier
    /// length and raw root are available, use [`Self::verify_leaf`] so the position is checked
    /// against the authenticated length before calling [`MerklePath::verify`].
    pub fn to_merkle_proof(&self, opening: &MmrProof) -> Result<MerkleProof, MmrError> {
        let proof_len = opening.forest().num_leaves();
        if proof_len != self.len {
            return Err(MmrError::InconsistentProofForest { proof: proof_len, frontier: self.len });
        }

        let peak_height = Forest::new(self.len)
            .expect("frontier length must be valid")
            .leaf_to_corresponding_tree(opening.position())
            .ok_or(MmrError::PositionNotFound(opening.position()))?;
        let peak_height =
            u8::try_from(peak_height).expect("peak height bounded by Forest::MAX_LEAVES");

        if opening.merkle_path().depth() != peak_height {
            return Err(MmrError::InvalidMerklePath(MerkleError::InvalidPathLength(
                peak_height as usize,
            )));
        }

        let mut nodes = opening.merkle_path().nodes().to_vec();
        nodes.extend(self.path_from_peak_to_root(opening.peak_index())?);

        Ok(MerkleProof::new(opening.leaf(), MerklePath::new(nodes)))
    }

    /// Appends a leaf to this frontier.
    ///
    /// # Errors
    /// Returns an error if appending would exceed the maximum supported forest size.
    pub fn append(&mut self, mut node: Word) -> Result<(), MmrError> {
        if self.len >= Forest::MAX_LEAVES {
            return Err(MmrError::ForestSizeExceeded {
                requested: self.len.saturating_add(1),
                max: Forest::MAX_LEAVES,
            });
        }

        let mut n = self.len;
        while n & 1 == 1 {
            let left = self.peaks.pop().expect("peak must exist");
            node = Poseidon2::merge(&[left, node]);
            n >>= 1;
        }
        self.peaks.push(node);
        self.len += 1;

        Ok(())
    }

    // UTILITIES
    // --------------------------------------------------------------------------------------------

    fn path_from_peak_to_root(&self, target_peak_idx: usize) -> Result<Vec<Word>, MmrError> {
        if target_peak_idx >= self.peaks.len() {
            return Err(MmrError::PeakOutOfBounds {
                peak_idx: target_peak_idx,
                peaks_len: self.peaks.len(),
            });
        }

        let frontier_depth = (usize::BITS - self.len.leading_zeros()) as u8;
        let mut acc = empty_subtree_root(0);
        let mut path = Vec::with_capacity(frontier_depth as usize);
        let mut peak_cursor = self.peaks.len();
        let mut contains_target = false;

        for level in 0..frontier_depth {
            if (self.len >> level) & 1 == 1 {
                peak_cursor -= 1;
                let peak = self.peaks[peak_cursor];
                if peak_cursor == target_peak_idx {
                    contains_target = true;
                    path.push(acc);
                } else if contains_target {
                    path.push(peak);
                }
                acc = Poseidon2::merge(&[peak, acc]);
            } else {
                let empty = empty_subtree_root(level);
                if contains_target {
                    path.push(empty);
                }
                acc = Poseidon2::merge(&[acc, empty]);
            }
        }

        Ok(path)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MmrPeaks> for MerkleFrontier {
    fn from(peaks: MmrPeaks) -> Self {
        let (forest, peaks) = peaks.into_parts();
        Self { len: forest.num_leaves(), peaks }
    }
}

impl From<&MmrPeaks> for MerkleFrontier {
    fn from(peaks: &MmrPeaks) -> Self {
        Self {
            len: peaks.num_leaves(),
            peaks: peaks.peaks().to_vec(),
        }
    }
}

impl From<MerkleFrontier> for MmrPeaks {
    fn from(frontier: MerkleFrontier) -> Self {
        frontier.into_legacy_peaks()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MerkleFrontier {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.len.write_into(target);
        self.peaks.write_into(target);
    }
}

impl Deserializable for MerkleFrontier {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = usize::read_from(source)?;
        if !Forest::is_valid_size(len) {
            return Err(DeserializationError::InvalidValue(format!(
                "frontier length {len} exceeds maximum {}",
                Forest::MAX_LEAVES
            )));
        }

        let num_peaks = usize::read_from(source)?;
        validate_frontier(len, num_peaks).map_err(|err| {
            DeserializationError::InvalidValue(format!("invalid frontier: {err}"))
        })?;

        let peaks = source.read_many_iter(num_peaks)?.collect::<Result<_, _>>()?;
        Ok(Self { len, peaks })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MerkleFrontier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct MerkleFrontierParts {
            len: usize,
            peaks: Vec<Word>,
        }

        let parts = MerkleFrontierParts::deserialize(deserializer)?;
        MerkleFrontier::new(parts.len, parts.peaks).map_err(serde::de::Error::custom)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn validate_frontier(len: usize, num_peaks: usize) -> Result<(), MmrError> {
    if !Forest::is_valid_size(len) {
        return Err(MmrError::ForestSizeExceeded { requested: len, max: Forest::MAX_LEAVES });
    }

    let forest = Forest::new(len).expect("frontier length has been validated");
    if forest.num_trees() != num_peaks {
        return Err(MmrError::InvalidPeaks(format!(
            "number of one bits in len is {} which does not equal peak length {}",
            forest.num_trees(),
            num_peaks
        )));
    }

    Ok(())
}

fn empty_subtree_root(height: u8) -> Word {
    *EmptySubtreeRoots::entry(height, 0)
}
