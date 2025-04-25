use super::mountain_range::MountainRange;

/// Iterate over the the trees within this forest, from smallest to largest.
///
/// Each item is a "sub-forest", containing only one tree.
pub struct TreeSizeIterator {
    value: MountainRange,
}

impl TreeSizeIterator {
    pub fn new(value: MountainRange) -> TreeSizeIterator {
        TreeSizeIterator { value }
    }
}

impl Iterator for TreeSizeIterator {
    type Item = MountainRange;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.value.smallest_tree_checked();

        if tree.is_empty() {
            None
        } else {
            self.value = self.value.without_trees(tree);
            Some(tree)
        }
    }
}

impl DoubleEndedIterator for TreeSizeIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        let tree = self.value.largest_tree();

        if tree.is_empty() {
            None
        } else {
            self.value = self.value.without_trees(tree);
            Some(tree)
        }
    }
}
