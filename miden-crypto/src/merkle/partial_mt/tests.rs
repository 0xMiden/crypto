use alloc::{collections::BTreeMap, vec::Vec};

use super::{
    super::{
        DefaultMerkleStore as MerkleStore, MerkleTree, NodeIndex, PartialMerkleTree,
        digests_to_words, int_to_node,
    },
    Deserializable, InnerNodeInfo, RpoDigest, Serializable, ValuePath,
};

// TEST DATA
// ================================================================================================

fn node_at(depth:u8, value: u64) -> NodeIndex {
    NodeIndex::new_unchecked(depth, value)
}

fn values8() -> [RpoDigest; 8] {
    [
    int_to_node(30),
    int_to_node(31),
    int_to_node(32),
    int_to_node(33),
    int_to_node(34),
    int_to_node(35),
    int_to_node(36),
    int_to_node(37),
]
}


// TESTS
// ================================================================================================

// For the Partial Merkle Tree tests we will use parts of the Merkle Tree which full form is
// illustrated below:
//
//              __________ root __________
//             /                          \
//       ____ 10 ____                ____ 11 ____
//      /            \              /            \
//     20            21            22            23
//   /    \        /    \        /    \        /    \
// (30)  (31)    (32)  (33)    (34)  (35)    (36)  (37)
//
// Where node number is a concatenation of its depth and index. For example, node with
// NodeIndex(3, 5) will be labeled as `35`. Leaves of the tree are shown as nodes with parenthesis
// (33).

/// Checks that creation of the PMT with `with_leaves()` constructor is working correctly.
#[test]
fn with_leaves() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let leaf_nodes_vec = vec![
        (node_at(2, 0), mt.get_node(node_at(2, 0)).unwrap()),
        (node_at(3, 2), mt.get_node(node_at(3, 2)).unwrap()),
        (node_at(3, 3), mt.get_node(node_at(3, 3)).unwrap()),
        (node_at(2, 2), mt.get_node(node_at(2, 2)).unwrap()),
        (node_at(2, 3), mt.get_node(node_at(2, 3)).unwrap()),
    ];

    let leaf_nodes: BTreeMap<NodeIndex, RpoDigest> = leaf_nodes_vec.into_iter().collect();

    let pmt = PartialMerkleTree::with_leaves(leaf_nodes).unwrap();

    assert_eq!(expected_root, pmt.root())
}

/// Checks that `with_leaves()` function returns an error when using incomplete set of nodes.
#[test]
fn err_with_leaves() {
    // node_at(2, 2) is missing
    let leaf_nodes_vec = vec![
        (node_at(2, 0), int_to_node(20)),
        (node_at(3, 2), int_to_node(32)),
        (node_at(3, 3), int_to_node(33)),
        (node_at(2, 3), int_to_node(23)),
    ];

    let leaf_nodes: BTreeMap<NodeIndex, RpoDigest> = leaf_nodes_vec.into_iter().collect();

    assert!(PartialMerkleTree::with_leaves(leaf_nodes).is_err());
}

/// Checks that root returned by `root()` function is equal to the expected one.
#[test]
fn get_root() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert_eq!(expected_root, pmt.root());
}

/// This test checks correctness of the `add_path()` and `get_path()` functions. First it creates a
/// PMT using `add_path()` by adding Merkle Paths from node 33 and node 22 to the empty PMT. Then
/// it checks that paths returned by `get_path()` function are equal to the expected ones.
#[test]
fn add_and_get_paths() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let expected_path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();
    let expected_path22 = ms.get_path(expected_root, node_at(2, 2)).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, expected_path33.value, expected_path33.path.clone()).unwrap();
    pmt.add_path(2, expected_path22.value, expected_path22.path.clone()).unwrap();

    let path33 = pmt.get_path(node_at(3, 3)).unwrap();
    let path22 = pmt.get_path(node_at(2, 2)).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_path33.path, path33);
    assert_eq!(expected_path22.path, path22);
    assert_eq!(expected_root, actual_root);
}

/// Checks that function `get_node` used on nodes 10 and 32 returns expected values.
#[test]
fn get_node() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert_eq!(ms.get_node(expected_root, node_at(3, 2)).unwrap(), pmt.get_node(node_at(3, 2)).unwrap());
    assert_eq!(ms.get_node(expected_root, node_at(1,0)).unwrap(), pmt.get_node(node_at(1,0)).unwrap());
}

/// Updates leaves of the PMT using `update_leaf()` function and checks that new root of the tree
/// is equal to the expected one.
#[test]
fn update_leaf() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let root = mt.root();

    let mut ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(root, node_at(3, 3)).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    let new_value32 = int_to_node(132);
    let expected_root = ms.set_node(root, node_at(3, 2), new_value32).unwrap().root;

    pmt.update_leaf(2, *new_value32).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);

    let new_value20 = int_to_node(120);
    let expected_root = ms.set_node(expected_root, node_at(2, 0), new_value20).unwrap().root;

    pmt.update_leaf(0, *new_value20).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);

    let new_value11 = int_to_node(111);
    let expected_root = ms.set_node(expected_root, node_at(1, 1), new_value11).unwrap().root;

    pmt.update_leaf(6, *new_value11).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);
}

/// Checks that paths of the PMT returned by `paths()` function are equal to the expected ones.
#[test]
fn get_paths() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();
    let path22 = ms.get_path(expected_root, node_at(2, 2)).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, path33.value, path33.path).unwrap();
    pmt.add_path(2, path22.value, path22.path).unwrap();
    // After PMT creation with path33 (33; 32, 20, 11) and path22 (22; 23, 10) we will have this
    // tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33. Hence overall we will have 5 paths -- one path
    // for each leaf.

    let leaves = [node_at(2, 0), node_at(2, 2), node_at(2, 3), node_at(3, 2), node_at(3, 3)];
    let expected_paths: Vec<(NodeIndex, ValuePath)> = leaves
        .iter()
        .map(|&leaf| {
            (
                leaf,
                ValuePath {
                    value: mt.get_node(leaf).unwrap(),
                    path: mt.get_path(leaf).unwrap(),
                },
            )
        })
        .collect();

    let actual_paths = pmt.to_paths();

    assert_eq!(expected_paths, actual_paths);
}

// Checks correctness of leaves determination when using the `leaves()` function.
#[test]
fn leaves() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();
    let path22 = ms.get_path(expected_root, node_at(2, 2)).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();
    // After PMT creation with path33 (33; 32, 20, 11) we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___            (11)
    //     /         \
    //   (20)        21
    //             /    \
    //           (32)  (33)
    //
    // Which have leaf nodes 11, 20, 32 and 33.

    let value11 = mt.get_node(node_at(1, 1)).unwrap();
    let value20 = mt.get_node(node_at(2, 0)).unwrap();
    let value32 = mt.get_node(node_at(3, 2)).unwrap();
    let value33 = mt.get_node(node_at(3, 3)).unwrap();

    let leaves = [(node_at(1, 1), value11), (node_at(2, 0), value20), (node_at(3, 2), value32), (node_at(3, 3), value33)];

    let expected_leaves = leaves.iter().copied();
    assert!(expected_leaves.eq(pmt.leaves()));

    pmt.add_path(2, path22.value, path22.path).unwrap();
    // After adding the path22 (22; 23, 10) to the existing PMT we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33.

    let value20 = mt.get_node(node_at(2, 0)).unwrap();
    let value22 = mt.get_node(node_at(2, 2)).unwrap();
    let value23 = mt.get_node(node_at(2, 3)).unwrap();
    let value32 = mt.get_node(node_at(3, 2)).unwrap();
    let value33 = mt.get_node(node_at(3, 3)).unwrap();

    let leaves = vec![
        (node_at(2, 0), value20),
        (node_at(2, 2), value22),
        (node_at(2, 3), value23),
        (node_at(3, 2), value32),
        (node_at(3, 3), value33),
    ];

    let expected_leaves = leaves.iter().copied();
    assert!(expected_leaves.eq(pmt.leaves()));
}

/// Checks that nodes of the PMT returned by `inner_nodes()` function are equal to the expected
/// ones.
#[test]
fn test_inner_node_iterator() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();
    let path22 = ms.get_path(expected_root, node_at(2, 2)).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    // get actual inner nodes
    let actual: Vec<InnerNodeInfo> = pmt.inner_nodes().collect();

    let expected_n00 = mt.root();
    let expected_n10 = mt.get_node(node_at(1,0)).unwrap();
    let expected_n11 = mt.get_node(node_at(1, 1)).unwrap();
    let expected_n20 = mt.get_node(node_at(2, 0)).unwrap();
    let expected_n21 = mt.get_node(node_at(2, 1)).unwrap();
    let expected_n32 = mt.get_node(node_at(3, 2)).unwrap();
    let expected_n33 = mt.get_node(node_at(3, 3)).unwrap();

    // create vector of the expected inner nodes
    let mut expected = vec![
        InnerNodeInfo {
            value: expected_n00,
            left: expected_n10,
            right: expected_n11,
        },
        InnerNodeInfo {
            value: expected_n10,
            left: expected_n20,
            right: expected_n21,
        },
        InnerNodeInfo {
            value: expected_n21,
            left: expected_n32,
            right: expected_n33,
        },
    ];

    assert_eq!(actual, expected);

    // add another path to the Partial Merkle Tree
    pmt.add_path(2, path22.value, path22.path).unwrap();

    // get new actual inner nodes
    let actual: Vec<InnerNodeInfo> = pmt.inner_nodes().collect();

    let expected_n22 = mt.get_node(node_at(2, 2)).unwrap();
    let expected_n23 = mt.get_node(node_at(2, 3)).unwrap();

    let info_11 = InnerNodeInfo {
        value: expected_n11,
        left: expected_n22,
        right: expected_n23,
    };

    // add new inner node to the existing vertor
    expected.insert(2, info_11);

    assert_eq!(actual, expected);
}

/// Checks that serialization and deserialization implementations for the PMT are working
/// correctly.
#[test]
fn serialization() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();
    let path22 = ms.get_path(expected_root, node_at(2, 2)).unwrap();

    let pmt = PartialMerkleTree::with_paths([
        (3, path33.value, path33.path),
        (2, path22.value, path22.path),
    ])
    .unwrap();

    let serialized_pmt = pmt.to_bytes();
    let deserialized_pmt = PartialMerkleTree::read_from_bytes(&serialized_pmt).unwrap();

    assert_eq!(deserialized_pmt, pmt);
}

/// Checks that deserialization fails with incorrect data.
#[test]
fn err_deserialization() {
    let mut tree_bytes: Vec<u8> = vec![5];
    tree_bytes.append(&mut node_at(2, 0).to_bytes());
    tree_bytes.append(&mut int_to_node(20).to_bytes());

    tree_bytes.append(&mut node_at(2, 1).to_bytes());
    tree_bytes.append(&mut int_to_node(21).to_bytes());

    // node with depth 1 could have index 0 or 1, but it has 2
    tree_bytes.append(&mut vec![1, 2]);
    tree_bytes.append(&mut int_to_node(11).to_bytes());

    assert!(PartialMerkleTree::read_from_bytes(&tree_bytes).is_err());
}

/// Checks that addition of the path with different root will cause an error.
#[test]
fn err_add_path() {
    let path33 = vec![int_to_node(1), int_to_node(2), int_to_node(3)].into();
    let path22 = vec![int_to_node(4), int_to_node(5)].into();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, int_to_node(6), path33).unwrap();

    assert!(pmt.add_path(2, int_to_node(7), path22).is_err());
}

/// Checks that the request of the node which is not in the PMT will cause an error.
#[test]
fn err_get_node() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.get_node(node_at(2, 2)).is_err());
    assert!(pmt.get_node(node_at(2, 3)).is_err());
    assert!(pmt.get_node(node_at(3, 0)).is_err());
    assert!(pmt.get_node(node_at(3, 1)).is_err());
}

/// Checks that the request of the path from the leaf which is not in the PMT will cause an error.
#[test]
fn err_get_path() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.get_path(node_at(2, 2)).is_err());
    assert!(pmt.get_path(node_at(2, 3)).is_err());
    assert!(pmt.get_path(node_at(3, 0)).is_err());
    assert!(pmt.get_path(node_at(3, 1)).is_err());
}

#[test]
fn err_update_leaf() {
    let mt = MerkleTree::new(digests_to_words(&values8())).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, node_at(3, 3)).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.update_leaf(8, *int_to_node(38)).is_err());
}