
use super::*;


modtests
)]#[cfg(test{
    use super::*;
    use crate::merkle::{Smt, SmtLeaf};
    use crate::hash::rpo::RpoDigest;

    // Helper function to create a test key-value pair
    fn test_pair(n: u64) -> (Word, Word) {
        let key = RpoDigest::new([n.into(), 0.into(), 0.into(), 0.into()]).into();
        let value = RpoDigest::new([n.into(), n.into(), 0.into(), 0.into()]).into();
        (key, value)
    }

    // Create a mock SMT with some initial data
    fn create_mock_smt() -> Smt {
        let mut smt = Smt::new();

        // Insert some initial values
        for i in 1..=5 {
            let (key, value) = test_pair(i);
            smt.insert(key, value);
        }

        smt
    }

    // Create test mutation sets
    fn create_mutation_sets(smt: &Smt) -> (MutationSet<SMT_DEPTH, Word, Word>,
                                           MutationSet<SMT_DEPTH, Word, Word>,
                                           MutationSet<SMT_DEPTH, Word, Word>) {
        // First mutation set: Update existing keys and add new ones
        let mut smt1 = smt.clone();
        let old_root1 = smt1.root();

        let (key6, value6) = test_pair(6);xxx
