/// The representation of a single Merkle path.
use alloc::vec::Vec;

use super::{super::MerklePath, MmrError, forest::Forest};
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

    /// Returns a new [MmrPath] adjusted for a smaller target forest.
    ///
    /// This is useful when receiving authenticated data from a larger MMR and needing to adjust
    /// the path for a smaller MMR. The path is trimmed to include only the nodes relevant
    /// for the target forest.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target forest does not include this path's position
    /// - The target forest is larger than the current forest
    pub fn with_forest(&self, target_forest: Forest) -> Result<MmrPath, MmrError> {
        // Validate target forest includes the position
        if target_forest.num_leaves() <= self.position {
            return Err(MmrError::PositionNotFound(self.position));
        }

        // Validate target forest is not larger than current forest
        if target_forest > self.forest {
            return Err(MmrError::ForestOutOfBounds(
                target_forest.num_leaves(),
                self.forest.num_leaves(),
            ));
        }

        // Get expected depth for the target forest
        let target_depth = target_forest
            .leaf_to_corresponding_tree(self.position)
            .expect("position is in target forest") as usize;

        // Trim the merkle path to the target depth
        let trimmed_nodes: Vec<_> =
            self.merkle_path.nodes().iter().take(target_depth).copied().collect();
        let trimmed_path = MerklePath::new(trimmed_nodes);

        Ok(MmrPath::new(target_forest, self.position, trimmed_path))
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

    /// Returns a new [MmrProof] adjusted for a smaller target forest.
    ///
    /// This is useful when receiving authenticated data from a larger MMR and needing to adjust
    /// the proof for a smaller MMR. The path is trimmed to include only the nodes relevant
    /// for the target forest.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target forest does not include this proof's position
    /// - The target forest is larger than the current forest
    pub fn with_forest(&self, target_forest: Forest) -> Result<MmrProof, MmrError> {
        let adjusted_path = self.path.with_forest(target_forest)?;
        Ok(MmrProof::new(adjusted_path, self.leaf))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{MerklePath, MmrPath, MmrProof};
    use crate::{
        Word,
        merkle::{int_to_node, mmr::forest::Forest},
    };

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

    #[test]
    fn test_mmr_path_with_forest() {
        // Create a path for position 2 in a forest of 15 leaves (tree of depth 3)
        let large_forest = Forest::new(15);
        let node0 = int_to_node(1);
        let node1 = int_to_node(2);
        let node2 = int_to_node(3);
        let nodes = vec![node0, node1, node2];
        let path = MmrPath::new(large_forest, 2, MerklePath::new(nodes));

        // Adjust for a smaller forest of 7 leaves (tree of depth 2 for position 2)
        let small_forest = Forest::new(7);
        let adjusted = path.with_forest(small_forest).unwrap();

        assert_eq!(adjusted.forest(), small_forest);
        assert_eq!(adjusted.position(), 2);
        // Depth for position 2 in forest 7 is 2 (it's in the 4-leaf tree)
        assert_eq!(adjusted.merkle_path().depth(), 2);

        // Verify the actual nodes are the first 2 from the original path
        let adjusted_nodes = adjusted.merkle_path().nodes();
        assert_eq!(adjusted_nodes.len(), 2);
        assert_eq!(adjusted_nodes[0], node0);
        assert_eq!(adjusted_nodes[1], node1);
    }

    #[test]
    fn test_mmr_path_with_forest_errors() {
        let forest = Forest::new(7);
        let path = MmrPath::new(forest, 2, MerklePath::default());

        // Error: target forest doesn't include position
        let small_forest = Forest::new(2);
        assert!(path.with_forest(small_forest).is_err());

        // Error: target forest is larger than current
        let large_forest = Forest::new(15);
        assert!(path.with_forest(large_forest).is_err());

        // Same forest should work
        assert!(path.with_forest(forest).is_ok());
    }

    #[test]
    fn test_mmr_proof_with_forest() {
        // Create a proof for position 2 in a forest of 15 leaves
        let large_forest = Forest::new(15);
        let nodes = vec![int_to_node(1), int_to_node(2), int_to_node(3)];
        let path = MmrPath::new(large_forest, 2, MerklePath::new(nodes));
        let leaf = int_to_node(42);
        let proof = MmrProof::new(path, leaf);

        // Adjust for a smaller forest
        let small_forest = Forest::new(7);
        let adjusted = proof.with_forest(small_forest).unwrap();

        assert_eq!(adjusted.forest(), small_forest);
        assert_eq!(adjusted.position(), 2);
        assert_eq!(adjusted.leaf(), leaf);
        assert_eq!(adjusted.merkle_path().depth(), 2);
    }
}
