#[cfg(test)]
mod proptest_tests {
    use alloc::vec::Vec;
    use core::num::NonZero;

    use proptest::prelude::*;

    use super::super::{MerklePath, SparseMerklePath, Word};
    use crate::{
        Felt,
        merkle::SMT_MAX_DEPTH,
    };

    // Arbitrary instance for Word
    impl Arbitrary for Word {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop::collection::vec(any::<u64>(), 4)
                .prop_map(|vals| {
                    Word::new([
                        Felt::new(vals[0]),
                        Felt::new(vals[1]),
                        Felt::new(vals[2]),
                        Felt::new(vals[3]),
                    ])
                })
                .boxed()
        }
    }

    // Arbitrary instance for MerklePath
    impl Arbitrary for MerklePath {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop::collection::vec(any::<Word>(), 0..=SMT_MAX_DEPTH as usize)
                .prop_map(MerklePath::new)
                .boxed()
        }
    }

    // Arbitrary instance for SparseMerklePath
    impl Arbitrary for SparseMerklePath {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (0..=SMT_MAX_DEPTH as usize)
                .prop_flat_map(|depth| {
                    // Generate a bitmask for empty nodes - avoid overflow
                    let max_mask = if depth > 0 && depth < 64 { (1u64 << depth) - 1 } else if depth == 64 { u64::MAX } else { 0 };
                    let empty_nodes_mask = prop::num::u64::ANY.prop_map(move |mask| mask & max_mask);

                    // Generate non-empty nodes based on the mask
                    empty_nodes_mask.prop_flat_map(move |mask| {
                        let empty_count = mask.count_ones() as usize;
                        let non_empty_count = depth.saturating_sub(empty_count);
                        
                        prop::collection::vec(any::<Word>(), non_empty_count)
                            .prop_map(move |nodes| {
                                SparseMerklePath::from_parts(mask, nodes).unwrap()
                            })
                    })
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn sparse_merkle_path_roundtrip_equivalence(path in any::<MerklePath>()) {
            // Convert MerklePath to SparseMerklePath and back
            let sparse_result = SparseMerklePath::try_from(path.clone());
            if path.depth() <= SMT_MAX_DEPTH {
                let sparse = sparse_result.unwrap();
                let reconstructed = MerklePath::from(sparse);
                prop_assert_eq!(path, reconstructed);
            } else {
                prop_assert!(sparse_result.is_err());
            }
        }

        #[test]
        fn merkle_path_roundtrip_equivalence(sparse in any::<SparseMerklePath>()) {
            // Convert SparseMerklePath to MerklePath and back
            let merkle = MerklePath::from(sparse.clone());
            let reconstructed = SparseMerklePath::try_from(merkle.clone()).unwrap();
            prop_assert_eq!(sparse, reconstructed);
        }

        #[test]
        fn depth_consistency(path in any::<MerklePath>()) {
            if path.depth() <= SMT_MAX_DEPTH {
                let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
                prop_assert_eq!(path.depth(), sparse.depth());
            }
        }

        #[test]
        fn node_access_consistency(path in any::<MerklePath>()) {
            if path.depth() == 0 || path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
            
            // Test node access at each depth
            for depth_val in 1..=path.depth() {
                let depth = NonZero::new(depth_val).unwrap();
                let merkle_node = path.at_depth(depth);
                let sparse_node = sparse.at_depth(depth);
                
                match (merkle_node, sparse_node) {
                    (Some(m), Ok(s)) => prop_assert_eq!(m, s),
                    (None, Err(_)) => {},
                    _ => prop_assert!(false, "Inconsistent node access at depth {}", depth_val),
                }
            }
        }

        #[test]
        fn iterator_consistency(path in any::<MerklePath>()) {
            if path.depth() == 0 || path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
            
            let merkle_nodes: Vec<_> = path.iter().collect();
            let sparse_nodes: Vec<_> = sparse.iter().collect();
            
            prop_assert_eq!(merkle_nodes.len(), sparse_nodes.len());
            for (m, s) in merkle_nodes.iter().zip(sparse_nodes.iter()) {
                prop_assert_eq!(*m, s);
            }
        }

        #[test]
        fn compute_root_consistency(
            path in any::<MerklePath>(),
            index in any::<u64>(),
            node in any::<Word>()
        ) {
            if path.depth() == 0 || path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
            
            let merkle_root = path.compute_root(index, node);
            let sparse_root = sparse.compute_root(index, node);
            
            match (merkle_root, sparse_root) {
                (Ok(m), Ok(s)) => prop_assert_eq!(m, s),
                (Err(e1), Err(e2)) => {
                    // Both should have the same error type
                    prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                },
                _ => prop_assert!(false, "Inconsistent compute_root results"),
            }
        }

        #[test]
        fn verify_consistency(
            path in any::<MerklePath>(),
            index in any::<u64>(),
            node in any::<Word>(),
            root in any::<Word>()
        ) {
            if path.depth() == 0 || path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
            
            let merkle_verify = path.verify(index, node, &root);
            let sparse_verify = sparse.verify(index, node, &root);
            
            match (merkle_verify, sparse_verify) {
                (Ok(()), Ok(())) => {},
                (Err(e1), Err(e2)) => {
                    // Both should have the same error type
                    prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                },
                _ => prop_assert!(false, "Inconsistent verify results"),
            }
        }

        #[test]
        fn authenticated_nodes_consistency(
            path in any::<MerklePath>(),
            index in any::<u64>(),
            node in any::<Word>()
        ) {
            if path.depth() == 0 || path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();
            
            let merkle_result = path.authenticated_nodes(index, node);
            let sparse_result = sparse.authenticated_nodes(index, node);
            
            match (merkle_result, sparse_result) {
                (Ok(m_iter), Ok(s_iter)) => {
                    let merkle_nodes: Vec<_> = m_iter.collect();
                    let sparse_nodes: Vec<_> = s_iter.collect();
                    prop_assert_eq!(merkle_nodes.len(), sparse_nodes.len());
                    for (m, s) in merkle_nodes.iter().zip(sparse_nodes.iter()) {
                        prop_assert_eq!(m, s);
                    }
                },
                (Err(e1), Err(e2)) => {
                    prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                },
                _ => prop_assert!(false, "Inconsistent authenticated_nodes results"),
            }
        }

        #[test]
        fn equality_consistency(path1 in any::<MerklePath>(), path2 in any::<MerklePath>()) {
            if path1.depth() > SMT_MAX_DEPTH || path2.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse1 = SparseMerklePath::try_from(path1.clone()).unwrap();
            let sparse2 = SparseMerklePath::try_from(path2.clone()).unwrap();
            
            // Test equality between different representations
            prop_assert_eq!(path1 == path2, sparse1 == sparse2);
            prop_assert_eq!(path1 == sparse2, sparse1 == path2);
        }
    }

    #[test]
    fn test_api_differences() {
        // This test documents API differences between MerklePath and SparseMerklePath
        
        // 1. MerklePath has Deref/DerefMut to Vec<Word> - SparseMerklePath does not
        let merkle = MerklePath::new(vec![Word::default(); 3]);
        let _vec_ref: &Vec<Word> = &merkle; // This works due to Deref
        let _vec_mut: &mut Vec<Word> = &mut merkle.clone(); // This works due to DerefMut
        
        // 2. SparseMerklePath has from_parts() - MerklePath uses new() or from_iter()
        let sparse = SparseMerklePath::from_parts(0b101, vec![Word::default(); 2]).unwrap();
        assert_eq!(sparse.depth(), 4); // depth is 4 because mask has bits set up to depth 4
        
        // 3. SparseMerklePath has from_sized_iter() - MerklePath uses from_iter()
        let nodes = vec![Word::default(); 3];
        let sparse_from_iter = SparseMerklePath::from_sized_iter(nodes.clone()).unwrap();
        let merkle_from_iter = MerklePath::from_iter(nodes);
        assert_eq!(sparse_from_iter.depth(), merkle_from_iter.depth());
    }
}