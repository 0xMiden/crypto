use super::forest::Forest;

/// Iterate over the the trees within this forest, from smallest to largest.
///
/// Each item is a "sub-forest", containing only one tree.
pub struct TreeSizeIterator {
    value: Forest,
}

impl TreeSizeIterator {
    pub fn new(value: Forest) -> TreeSizeIterator {
        TreeSizeIterator { value }
    }
}

impl Iterator for TreeSizeIterator {
    type Item = Forest;

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
        let tree = self.value.largest_tree_checked();

        if tree.is_empty() {
            None
        } else {
            self.value = self.value.without_trees(tree);
            Some(tree)
        }
    }
}
