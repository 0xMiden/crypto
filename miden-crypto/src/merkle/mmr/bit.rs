use super::forest::Forest;

/// Iterate over the bits of a `usize` and yields the bit positions for the true bits.
pub struct TrueBitPositionIterator {
    value: Forest,
}

impl TrueBitPositionIterator {
    pub fn new(value: Forest) -> TrueBitPositionIterator {
        TrueBitPositionIterator { value }
    }
}

impl Iterator for TrueBitPositionIterator {
    type Item = Forest;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.value.smallest_tree_checked();

        if tree.is_empty() {
            None
        } else {
            self.value ^= tree;
            Some(tree)
        }
    }
}

impl DoubleEndedIterator for TrueBitPositionIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.value.largest_tree_checked();

        if tree.is_empty() {
            None
        } else {
            self.value ^= tree;
            Some(tree)
        }
    }
}
