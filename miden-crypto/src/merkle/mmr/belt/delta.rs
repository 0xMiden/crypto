use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{BeltProof, BeltSummary, MmrError, proof::*, shape::*};
use crate::Word;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrBeltDelta {
    pub(super) from_num_leaves: usize,
    pub(super) to_num_leaves: usize,
    pub(super) new_tail_peaks: Vec<Word>,
    pub(super) merge_auth: BTreeMap<(usize, usize), Word>,
}

impl MmrBeltDelta {
    pub fn from_parts<I>(
        from_num_leaves: usize,
        to_num_leaves: usize,
        new_tail_peaks: Vec<Word>,
        merge_auth_nodes: I,
    ) -> Result<Self, MmrError>
    where
        I: IntoIterator<Item = ((usize, usize), Word)>,
    {
        if from_num_leaves > to_num_leaves {
            return Err(MmrError::ForestOutOfBounds(from_num_leaves, to_num_leaves));
        }
        // `to_num_leaves` bounds `from_num_leaves`, so validating it guards both shape derivations.
        validate_num_leaves(to_num_leaves)?;

        let common = common_peak_prefix_len(from_num_leaves, to_num_leaves);
        let new_len = shape_len_for_num_leaves(to_num_leaves);
        if common + new_tail_peaks.len() != new_len {
            return Err(MmrError::InvalidUpdate);
        }

        let mut merge_auth = BTreeMap::new();
        for ((start, height), value) in merge_auth_nodes {
            if merge_auth.insert((start, height), value).is_some() {
                return Err(MmrError::InvalidUpdate);
            }
        }

        Ok(Self {
            from_num_leaves,
            to_num_leaves,
            new_tail_peaks,
            merge_auth,
        })
    }

    pub fn from_num_leaves(&self) -> usize {
        self.from_num_leaves
    }

    pub fn to_num_leaves(&self) -> usize {
        self.to_num_leaves
    }

    pub fn new_tail_peaks(&self) -> &[Word] {
        &self.new_tail_peaks
    }

    pub fn merge_auth_nodes(&self) -> impl Iterator<Item = ((usize, usize), Word)> + '_ {
        self.merge_auth
            .iter()
            .map(|(&(start, height), &value)| ((start, height), value))
    }

    pub fn num_merge_auth_nodes(&self) -> usize {
        self.merge_auth.len()
    }

    pub fn verify_transition(
        &self,
        old_summary: &BeltSummary,
        new_summary: &BeltSummary,
    ) -> Result<bool, MmrError> {
        if old_summary.num_leaves() != self.from_num_leaves
            || new_summary.num_leaves() != self.to_num_leaves
        {
            return Ok(false);
        }

        let old_shape = shape_mountains(self.from_num_leaves);
        let new_shape = shape_mountains(self.to_num_leaves);
        let common = common_peak_prefix_len_from_shapes(&old_shape, &new_shape);

        let roots = self.apply_with_common(common, old_summary.roots())?;
        let derived = BeltSummary::from_roots(self.to_num_leaves, &roots)?;

        Ok(&derived == new_summary
            && self.authenticates_absorbed_roots(
                old_summary,
                new_summary,
                &old_shape,
                &new_shape,
                common,
            )?)
    }

    fn authenticates_absorbed_roots(
        &self,
        old_summary: &BeltSummary,
        new_summary: &BeltSummary,
        old_shape: &[ShapeMountain],
        new_shape: &[ShapeMountain],
        common: usize,
    ) -> Result<bool, MmrError> {
        let mut required = BTreeSet::new();
        for (old_mountain, &old_root) in old_shape.iter().zip(old_summary.roots()).skip(common) {
            let new_idx = shape_mountain_for_position(new_shape, old_mountain.start)
                .ok_or(MmrError::InvalidUpdate)?;
            let new_mountain = new_shape[new_idx];
            let old_end = old_mountain
                .start
                .checked_add(old_mountain.size())
                .and_then(|end| end.checked_sub(1))
                .ok_or(MmrError::InvalidUpdate)?;
            if new_mountain.height < old_mountain.height || !new_mountain.contains_position(old_end)
            {
                return Err(MmrError::InvalidUpdate);
            }

            let mut root = old_root;
            for (side, sibling_start, height) in
                climb_to_peak(old_mountain.start, old_mountain.height, new_mountain.height)
            {
                required.insert((sibling_start, height));
                let &sibling =
                    self.merge_auth.get(&(sibling_start, height)).ok_or(MmrError::InvalidUpdate)?;
                root = merge_with_side(side, root, sibling);
            }

            if root != new_summary.roots()[new_idx] {
                return Ok(false);
            }
        }

        // Every required key is present (the climb would have errored otherwise), so an equal count
        // rejects deltas padded with auth nodes outside the required set.
        if self.merge_auth.len() != required.len() {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn apply(&self, old_peaks: &[Word]) -> Result<Vec<Word>, MmrError> {
        let common = common_peak_prefix_len(self.from_num_leaves, self.to_num_leaves);
        self.apply_with_common(common, old_peaks)
    }

    fn apply_with_common(&self, common: usize, old_peaks: &[Word]) -> Result<Vec<Word>, MmrError> {
        let old_len = shape_len_for_num_leaves(self.from_num_leaves);
        if old_peaks.len() != old_len {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {old_len} peaks for {} leaves but got {}",
                self.from_num_leaves,
                old_peaks.len()
            )));
        }

        let new_len = shape_len_for_num_leaves(self.to_num_leaves);
        if common + self.new_tail_peaks.len() != new_len {
            return Err(MmrError::InvalidUpdate);
        }

        let mut peaks = old_peaks[..common].to_vec();
        peaks.extend_from_slice(&self.new_tail_peaks);

        Ok(peaks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMmrBelt {
    num_leaves: usize,
    peaks: Vec<Word>,
    tracked: BTreeMap<usize, TrackedLeaf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedLeaf {
    leaf: Word,
    mountain_start: usize,
    mountain_height: usize,
    within_path: Vec<BeltProofNode>,
}

impl PartialMmrBelt {
    pub fn from_peaks(num_leaves: usize, peaks: Vec<Word>) -> Result<Self, MmrError> {
        validate_num_leaves(num_leaves)?;
        let expected = shape_len_for_num_leaves(num_leaves);
        if peaks.len() != expected {
            return Err(MmrError::InvalidPeaks(format!(
                "expected {expected} peaks for {num_leaves} leaves but got {}",
                peaks.len()
            )));
        }

        Ok(Self {
            num_leaves,
            peaks,
            tracked: BTreeMap::new(),
        })
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn peaks(&self) -> &[Word] {
        &self.peaks
    }

    pub fn summary(&self) -> BeltSummary {
        BeltSummary::from_roots(self.num_leaves, &self.peaks)
            .expect("partial mountain-order summary must match the current shape")
    }

    pub fn is_tracked(&self, pos: usize) -> bool {
        self.tracked.contains_key(&pos)
    }

    pub fn num_tracked(&self) -> usize {
        self.tracked.len()
    }

    pub fn get(&self, pos: usize) -> Option<Word> {
        self.tracked.get(&pos).map(|tracked| tracked.leaf)
    }

    pub fn track(&mut self, proof: &BeltProof) -> Result<(), MmrError> {
        if !proof.verify(&self.summary()) {
            return Err(MmrError::PeakPathMismatch);
        }

        let shape = shape_mountains(self.num_leaves);
        let mountain_idx = shape_mountain_for_position(&shape, proof.position())
            .ok_or(MmrError::PositionNotFound(proof.position()))?;
        let mountain = shape[mountain_idx];

        self.tracked.insert(
            proof.position(),
            TrackedLeaf {
                leaf: proof.leaf(),
                mountain_start: mountain.start,
                mountain_height: mountain.height,
                within_path: proof.nodes[..mountain.height].to_vec(),
            },
        );

        Ok(())
    }

    pub fn untrack(&mut self, pos: usize) -> bool {
        self.tracked.remove(&pos).is_some()
    }

    pub fn open(&self, pos: usize) -> Result<Option<BeltProof>, MmrError> {
        let Some(tracked) = self.tracked.get(&pos) else {
            return Ok(None);
        };

        let shape = shape_mountains(self.num_leaves);
        let mountain_idx =
            shape_mountain_for_position(&shape, pos).ok_or(MmrError::PositionNotFound(pos))?;

        let mut nodes = tracked.within_path.clone();
        nodes.extend(bagging_path_nodes(&self.peaks, &shape_ranges(&shape), mountain_idx));

        Ok(Some(BeltProof { position: pos, leaf: tracked.leaf, nodes }))
    }

    pub fn apply_verified(
        &mut self,
        delta: &MmrBeltDelta,
        new_summary: &BeltSummary,
    ) -> Result<(), MmrError> {
        if !delta.verify_transition(&self.summary(), new_summary)? {
            return Err(MmrError::InvalidUpdate);
        }

        // `apply` is transactional, so a failure here cannot leave the view partially advanced.
        self.apply(delta)
    }

    pub fn apply(&mut self, delta: &MmrBeltDelta) -> Result<(), MmrError> {
        if delta.from_num_leaves() != self.num_leaves {
            return Err(MmrError::InvalidUpdate);
        }

        // Build the new state in locals and commit only after every fallible step succeeds.
        let new_peaks = delta.apply(&self.peaks)?;
        let new_num_leaves = delta.to_num_leaves();
        let new_shape = shape_mountains(new_num_leaves);

        let mut new_tracked = BTreeMap::new();
        for (&pos, tracked) in &self.tracked {
            let mountain_idx = shape_mountain_for_position(&new_shape, pos)
                .ok_or(MmrError::PositionNotFound(pos))?;
            let new_mountain = new_shape[mountain_idx];

            let mut within_path = tracked.within_path.clone();
            for (side, sibling_start, height) in
                climb_to_peak(tracked.mountain_start, tracked.mountain_height, new_mountain.height)
            {
                let &value = delta
                    .merge_auth
                    .get(&(sibling_start, height))
                    .ok_or(MmrError::InvalidUpdate)?;
                within_path.push(BeltProofNode { value, side });
            }

            new_tracked.insert(
                pos,
                TrackedLeaf {
                    leaf: tracked.leaf,
                    mountain_start: new_mountain.start,
                    mountain_height: new_mountain.height,
                    within_path,
                },
            );
        }

        self.peaks = new_peaks;
        self.num_leaves = new_num_leaves;
        self.tracked = new_tracked;

        Ok(())
    }
}
