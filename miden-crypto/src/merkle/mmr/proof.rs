/// The representation of a single Merkle path.
use super::super::MerklePath;
use super::forest::Forest;

// MMR PROOF
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
/// Represents a proof for a leaf in a Merkle Mountain Range (MMR).
///
/// Contains the leaf's global position, the forest state, and the associated Merkle path.
pub struct MmrProof {
    /// The state of the MMR when the MmrProof was created.
    pub forest: Forest,

    /// The position of the leaf value on this MmrProof.
    pub position: usize,

    /// The Merkle opening, starting from the value's sibling up to and excluding the root of the
    /// responsible tree.
    pub merkle_path: MerklePath,
}

impl MmrProof {
    /// Converts the leaf global position into a local position that can be used to verify the
    /// merkle_path.
    pub fn relative_pos(&self) -> usize {
        self.forest
            .leaf_relative_position(self.position)
            .expect("position must be part of the forest")
    }

    /// Returns index of the MMR peak against which the Merkle path in this proof can be verified.
    pub fn peak_index(&self) -> usize {
        self.forest.tree_index(self.position)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{MerklePath, MmrProof};
    use crate::merkle::mmr::forest::Forest;

    #[test]
    fn test_peak_index() {
        // --- single peak forest ---------------------------------------------
        let forest = Forest::new(11);

        // the first 4 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // --- forest with non-consecutive peaks ------------------------------
        let forest = Forest::new(11);

        // the first 8 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 8..10 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 10);
        assert_eq!(proof.peak_index(), 2);

        // --- forest with consecutive peaks ----------------------------------
        let forest = Forest::new(7);

        // the first 4 leaves belong to peak 0
        for position in 0..4 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 4..6 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 6);
        assert_eq!(proof.peak_index(), 2);
    }

    fn make_dummy_proof(forest: Forest, position: usize) -> MmrProof {
        MmrProof {
            forest,
            position,
            merkle_path: MerklePath::default(),
        }
    }
}
