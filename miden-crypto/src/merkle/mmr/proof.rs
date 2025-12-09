/// The representation of a single Merkle path.
use super::super::MerklePath;
use super::forest::Forest;
use crate::Word;

// MMR PROOF
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrPath {
    /// The state of the MMR when the MMR path was created.
    forest: Forest,

    /// The position of the leaf value within the MMR.
    position: usize,

    /// The Merkle opening, starting from the value's sibling up to and excluding the root of the
    /// responsible tree.
    merkle_path: MerklePath,
}

impl MmrPath {
    /// Creates a new `MmrPath` with the given forest, position, and merkle path.
    pub fn new(forest: Forest, position: usize, merkle_path: MerklePath) -> Self {
        Self { forest, position, merkle_path }
    }

    /// Returns the state of the MMR when the MMR path was created.
    pub fn forest(&self) -> Forest {
        self.forest
    }

    /// Returns the position of the leaf value within the MMR.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the Merkle opening, starting from the value's sibling up to and excluding the root
    /// of the responsible tree.
    pub fn merkle_path(&self) -> &MerklePath {
        &self.merkle_path
    }

    /// Converts the leaf global position into a local position that can be used to verify the
    /// Merkle path.
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

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrProof {
    /// The Merkle path data describing how to authenticate the leaf.
    path: MmrPath,

    /// The leaf value that was opened.
    leaf: Word,
}

impl MmrProof {
    /// Creates a new `MmrProof` with the given path and leaf.
    pub fn new(path: MmrPath, leaf: Word) -> Self {
        Self { path, leaf }
    }

    /// Returns the Merkle path data describing how to authenticate the leaf.
    pub fn path(&self) -> &MmrPath {
        &self.path
    }

    /// Returns the leaf value that was opened.
    pub fn leaf(&self) -> Word {
        self.leaf
    }

    /// Returns the state of the MMR when the proof was created.
    pub fn forest(&self) -> Forest {
        self.path.forest()
    }

    /// Returns the position of the leaf value within the MMR.
    pub fn position(&self) -> usize {
        self.path.position()
    }

    /// Returns the Merkle opening, starting from the value's sibling up to and excluding the root
    /// of the responsible tree.
    pub fn merkle_path(&self) -> &MerklePath {
        self.path.merkle_path()
    }

    /// Converts the leaf global position into a local position that can be used to verify the
    /// merkle_path.
    pub fn relative_pos(&self) -> usize {
        self.path.relative_pos()
    }

    /// Returns index of the MMR peak against which the Merkle path in this proof can be verified.
    pub fn peak_index(&self) -> usize {
        self.path.peak_index()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{MerklePath, MmrPath, MmrProof};
    use crate::{Word, merkle::mmr::forest::Forest};

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
        let path = MmrPath::new(forest, position, MerklePath::default());
        MmrProof::new(path, Word::empty())
    }
}
