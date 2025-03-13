pub struct Forest(u64);

// TODO: add Felt conversion methods
impl Forest {
    /// Returns a count of leaves in the underlying MMR.
    pub fn num_leaves(&self) -> u64 {
        self.0
    }
    
    pub fn num_trees(&self) -> u64 {
        self.0.count_ones() as u64
    }

    /// Return the total number of nodes of a given forest
    ///
    /// Panics:
    ///
    /// This will panic if the forest has size greater than `usize::MAX / 2`
    pub fn num_nodes(&self) -> u64 {
        self.0 * 2 - self.num_trees()    
    }
}