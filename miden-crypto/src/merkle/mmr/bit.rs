use super::mountain_range::MountainRange;

/// Iterate over the the trees within this `MountainRange`, from smallest to largest.
///
/// Each item is a "sub-mountain range", containing only one tree.
pub struct TreeSizeIterator {
    inner: MountainRange,
}

impl TreeSizeIterator {
    pub fn new(value: MountainRange) -> TreeSizeIterator {
        TreeSizeIterator { inner: value }
    }
}

impl Iterator for TreeSizeIterator {
    type Item = MountainRange;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.inner.smallest_tree();

        if tree.is_empty() {
            None
        } else {
            self.inner = self.inner.without_trees(tree);
            Some(tree)
        }
    }
}

impl DoubleEndedIterator for TreeSizeIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.inner.largest_tree();

        if tree.is_empty() {
            None
        } else {
            self.inner = self.inner.without_trees(tree);
            Some(tree)
        }
    }
}
