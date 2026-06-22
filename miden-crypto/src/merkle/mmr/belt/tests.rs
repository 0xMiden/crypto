use alloc::{vec, vec::Vec};

use super::{
    BeltBaggingState, BeltHashArray, BeltSummary, ChangedMountain, HashIndex, MmrBelt,
    MmrBeltDelta, PartialMmrBelt, append_shape_in_place, bag_belt, bag_range,
    common_peak_prefix_len, hash_children, leaf_hash_index, node_hash_index, parent_hash_index,
    shape_mountain_index, shape_mountain_index_for_num_leaves, shape_mountains,
    shape_range_index_for_mountain, shape_range_index_for_num_leaves, shape_ranges,
};
use crate::{EMPTY_WORD, Word, hash::poseidon2::Poseidon2, merkle::int_to_node};

fn shape_heights(num_leaves: usize) -> Vec<usize> {
    shape_mountains(num_leaves).iter().map(|mountain| mountain.height).collect()
}

fn shape_hash_indices(num_leaves: usize) -> Vec<usize> {
    shape_mountains(num_leaves)
        .iter()
        .map(|mountain| node_hash_index(mountain.start, mountain.height).0)
        .collect()
}

fn hash_range(leaves: &[Word], start: usize, height: usize) -> Word {
    if height == 0 {
        return leaves[start];
    }

    let half = 1usize << (height - 1);
    Poseidon2::merge(&[
        hash_range(leaves, start, height - 1),
        hash_range(leaves, start + half, height - 1),
    ])
}

#[test]
fn belt_hash_indices_match_clojure_layout() {
    let leaf_indices = (0..6).map(|position| leaf_hash_index(position).0).collect::<Vec<_>>();
    assert_eq!(leaf_indices, vec![3, 5, 7, 9, 11, 13]);

    assert_eq!(parent_hash_index(HashIndex(3)), HashIndex(6));
    assert_eq!(parent_hash_index(HashIndex(5)), HashIndex(6));
    assert_eq!(hash_children(HashIndex(6)), (HashIndex(3), HashIndex(5)));

    assert_eq!(parent_hash_index(HashIndex(6)), HashIndex(12));
    assert_eq!(parent_hash_index(HashIndex(10)), HashIndex(12));
    assert_eq!(hash_children(HashIndex(12)), (HashIndex(6), HashIndex(10)));
}

#[test]
fn belt_shape_hash_indices_match_peak_layout() {
    assert_eq!(shape_hash_indices(1), vec![3]);
    assert_eq!(shape_hash_indices(2), vec![6]);
    assert_eq!(shape_hash_indices(3), vec![6, 7]);
    assert_eq!(shape_hash_indices(4), vec![6, 10]);
    assert_eq!(shape_hash_indices(5), vec![12, 11]);
    assert_eq!(shape_hash_indices(9), vec![12, 20, 19]);
    assert_eq!(shape_hash_indices(10), vec![12, 20, 22]);
}

#[test]
fn belt_hash_array_preserves_holes_with_compact_value_slots() {
    let mut hashes = BeltHashArray::default();
    let value = int_to_node(42);

    hashes.set(HashIndex(5), value);

    assert_eq!(hashes.get(HashIndex(4)), None);
    assert_eq!(hashes.get(HashIndex(5)), Some(value));
    assert_eq!(hashes.get(HashIndex(6)), None);
    assert_eq!(BeltHashArray::value_slot_bytes_for_testing(), size_of::<Word>());
}

#[test]
fn belt_shape_index_from_leaf_count_matches_shape_scan() {
    for num_leaves in 1..4096 {
        let shape = shape_mountains(num_leaves);
        for &mountain in &shape {
            assert_eq!(
                shape_mountain_index_for_num_leaves(num_leaves, mountain),
                shape_mountain_index(&shape, mountain),
                "index mismatch for {mountain:?} at {num_leaves} leaves"
            );
        }
    }
}

#[test]
fn belt_range_index_from_leaf_count_matches_range_scan() {
    for num_leaves in 1..4096 {
        let shape = shape_mountains(num_leaves);
        let ranges = shape_ranges(&shape);

        for mountain_idx in 0..shape.len() {
            assert_eq!(
                shape_range_index_for_num_leaves(num_leaves, mountain_idx),
                shape_range_index_for_mountain(&ranges, mountain_idx),
                "range index mismatch for mountain {mountain_idx} at {num_leaves} leaves"
            );
        }
    }
}

#[test]
fn belt_hash_array_stores_live_mountain_nodes() {
    let mut belt = MmrBelt::new();
    let leaves = (0..64).map(int_to_node).collect::<Vec<_>>();

    for leaf in leaves.iter().copied() {
        belt.add(leaf).unwrap();
    }

    for mountain in belt.ordered_mountains() {
        for height in 0..=mountain.height {
            let width = 1usize << height;
            for start in (mountain.start..mountain.start + mountain.size()).step_by(width) {
                assert_eq!(
                    belt.hashes.get(node_hash_index(start, height)),
                    Some(hash_range(&leaves, start, height)),
                    "missing hash for node [{start}, {})",
                    start + width
                );
            }
        }
    }
}

#[test]
fn belt_lazy_append_height_sequence() {
    let mut belt = MmrBelt::new();
    let expected = [
        vec![0],
        vec![1],
        vec![1, 0],
        vec![1, 1],
        vec![2, 0],
        vec![2, 1],
        vec![2, 1, 0],
        vec![2, 1, 1],
        vec![2, 2, 0],
        vec![2, 2, 1],
        vec![3, 1, 0],
        vec![3, 1, 1],
        vec![3, 2, 0],
    ];

    for (idx, expected_heights) in expected.into_iter().enumerate() {
        belt.add(int_to_node(idx as u64)).unwrap();
        assert_eq!(belt.mountain_heights(), expected_heights);
    }
}

#[test]
fn belt_append_performs_at_most_one_mountain_merge() {
    let mut belt = MmrBelt::new();

    for idx in 0..128 {
        let merge_count = belt.add(int_to_node(idx)).unwrap();
        assert!(merge_count <= 1);
    }
}

#[test]
fn belt_append_touches_constant_local_storage() {
    let mut belt = MmrBelt::new();

    for idx in 0..128 {
        let before = belt.storage_slots_for_testing();
        belt.add(int_to_node(idx)).unwrap();
        let after = belt.storage_slots_for_testing();

        assert!(after - before <= 2);
    }
}

#[test]
fn belt_tracks_rightmost_mergeable_pair_without_stale_stack() {
    let mut belt = MmrBelt::new();

    for idx in 0..512 {
        belt.add(int_to_node(idx)).unwrap();

        let mountains = belt.ordered_mountains();
        let expected = mountains
            .windows(2)
            .rev()
            .find(|pair| pair[0].height == pair[1].height)
            .map(|pair| (pair[0].start, pair[1].start));

        assert_eq!(belt.rightmost_mergeable_pair_for_testing(), expected, "after {idx}");
    }
}

#[test]
fn belt_range_splits_follow_mmb_rules() {
    let mut belt = MmrBelt::new();
    let expected = [
        vec![vec![0]],
        vec![vec![1]],
        vec![vec![1, 0]],
        vec![vec![1, 1]],
        vec![vec![2], vec![0]],
        vec![vec![2, 1]],
        vec![vec![2, 1, 0]],
        vec![vec![2, 1, 1]],
        vec![vec![2, 2], vec![0]],
        vec![vec![2, 2], vec![1]],
        vec![vec![3], vec![1, 0]],
        vec![vec![3], vec![1, 1]],
        vec![vec![3, 2], vec![0]],
        vec![vec![3, 2, 1]],
        vec![vec![3, 2, 1, 0]],
        vec![vec![3, 2, 1, 1]],
    ];

    for (idx, expected_ranges) in expected.into_iter().enumerate() {
        belt.add(int_to_node(idx as u64)).unwrap();
        assert_eq!(belt.range_heights(), expected_ranges);
    }
}

#[test]
fn belt_summary_root_is_stable_for_same_leaves() {
    let mut first = MmrBelt::new();
    let mut second = MmrBelt::new();

    for idx in 0..32 {
        let leaf = int_to_node(idx);
        first.add(leaf).unwrap();
        second.add(leaf).unwrap();
    }

    assert_eq!(first.summary().root(), second.summary().root());
    assert_eq!(first.summary().num_leaves(), 32);
}

#[test]
fn belt_openings_verify_for_all_leaves() {
    let mut belt = MmrBelt::new();
    let leaves = (0..37).map(int_to_node).collect::<Vec<_>>();
    for leaf in leaves.iter().copied() {
        belt.add(leaf).unwrap();
    }
    let summary = belt.summary();

    for (position, leaf) in leaves.into_iter().enumerate() {
        let proof = belt.open(position).unwrap();
        assert_eq!(proof.position(), position);
        assert_eq!(proof.leaf(), leaf);
        assert!(proof.verify(&summary));
    }
}

#[test]
fn belt_opening_rejects_wrong_leaf() {
    let mut belt = MmrBelt::new();
    for idx in 0..16 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let summary = belt.summary();
    let mut proof = belt.open(7).unwrap();

    proof.set_leaf_for_testing(int_to_node(999));

    assert!(!proof.verify(&summary));
}

#[test]
fn belt_proof_rejects_tampered_node() {
    let mut belt = MmrBelt::new();
    for idx in 0..37 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let summary = belt.summary();

    let pristine = belt.open(13).unwrap();
    assert!(pristine.verify(&summary));

    for node_idx in 0..pristine.node_count_for_testing() {
        let mut proof = belt.open(13).unwrap();
        proof.tamper_node_value_for_testing(node_idx, int_to_node(777_000 + node_idx as u64));
        assert!(!proof.verify(&summary), "tampering node {node_idx} should fail verification");
    }
}

#[test]
fn belt_opening_rejects_wrong_position() {
    let mut belt = MmrBelt::new();
    for idx in 0..37 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let summary = belt.summary();
    let mut proof = belt.open(7).unwrap();

    proof.set_position_for_testing(5);

    assert!(!proof.verify(&summary));
}

#[test]
fn belt_root_binds_shape_without_belt_domain_separation() {
    let mut belt = MmrBelt::new();
    for idx in 0..2 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let summary = belt.summary();
    let peaks = belt.peaks();
    assert_eq!(peaks.len(), 1);
    assert_ne!(summary.root(), peaks[0], "root must not be transparent to its peak");

    let mut bigger = MmrBelt::new();
    for idx in 0..3 {
        bigger.add(int_to_node(idx)).unwrap();
    }
    assert_ne!(bigger.summary().root(), summary.root());
}

#[test]
fn belt_second_bagging_uses_plain_merkle_merge() {
    let mut belt = MmrBelt::new();
    for idx in 0..5 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let shape = shape_mountains(belt.num_leaves());
    let peaks = belt.peaks();
    let range_roots = shape_ranges(&shape)
        .into_iter()
        .map(|range| bag_range(&peaks[range]))
        .collect::<Vec<_>>();
    assert!(range_roots.len() > 1);

    let expected = range_roots.iter().fold(EMPTY_WORD, |acc, &root| Poseidon2::merge(&[acc, root]));

    assert_eq!(belt.summary().root(), expected);
}

#[test]
fn belt_range_bagging_uses_plain_merkle_merge() {
    let mut belt = MmrBelt::new();
    for idx in 0..9 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let shape = shape_mountains(belt.num_leaves());
    let peaks = belt.peaks();
    let first_range = shape_ranges(&shape).into_iter().next().unwrap();
    assert!(first_range.len() > 1);

    let expected = peaks[first_range.clone()]
        .iter()
        .fold(EMPTY_WORD, |acc, &peak| Poseidon2::merge(&[acc, peak]));

    assert_eq!(bag_range(&peaks[first_range]), expected);
}

#[test]
fn belt_shape_derivation_matches_live_structure_across_pow2() {
    let mut belt = MmrBelt::new();
    let leaves = (0..4100u64).map(int_to_node).collect::<Vec<_>>();
    for leaf in leaves.iter().copied() {
        belt.add(leaf).unwrap();
    }
    let summary = belt.summary();

    for (position, leaf) in leaves.into_iter().enumerate() {
        let proof = belt.open(position).unwrap();
        assert_eq!(proof.leaf(), leaf, "leaf mismatch at {position}");
        assert!(proof.verify(&summary), "verify failed at position {position}");
    }
}

#[test]
fn belt_summary_from_peaks_matches_full_summary() {
    let mut belt = MmrBelt::new();
    for idx in 0..100 {
        belt.add(int_to_node(idx)).unwrap();
        let summary = belt.summary();
        let from_peaks = BeltSummary::from_peaks(summary.num_leaves(), &belt.peaks()).unwrap();
        assert_eq!(from_peaks, summary);
    }
}

#[test]
fn belt_summary_from_roots_matches_full_summary() {
    let mut belt = MmrBelt::new();
    for idx in 0..100 {
        belt.add(int_to_node(idx)).unwrap();
        let summary = belt.summary();
        let roots = summary.roots().to_vec();
        let from_roots = BeltSummary::from_roots(summary.num_leaves(), &roots).unwrap();
        assert_eq!(from_roots, summary);
    }
}

#[test]
fn belt_summary_exposes_mountain_order_roots() {
    let mut belt = MmrBelt::new();
    for idx in 0..37 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let summary = belt.summary();
    let peaks = belt.peaks();

    assert_eq!(summary.roots(), peaks.as_slice());
    assert_eq!(summary.commitment_root(), summary.root());
    assert_eq!(
        summary.commitment_root(),
        BeltSummary::from_roots(summary.num_leaves(), summary.roots()).unwrap().root()
    );
}

#[test]
fn belt_summary_uses_maintained_mountain_order_roots() {
    let mut belt = MmrBelt::new();
    for idx in 0..37 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let summary = belt.summary();
    let roots = belt.peaks();

    belt.hashes.clear();

    assert_eq!(belt.peaks(), roots);
    assert_eq!(belt.summary(), summary);
}

#[test]
fn belt_summary_carries_explicit_range_bagging_state() {
    let mut belt = MmrBelt::new();
    for idx in 0..190 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let summary = belt.summary();
    let shape = shape_mountains(summary.num_leaves());
    let expected_range_roots = shape_ranges(&shape)
        .into_iter()
        .map(|range| bag_range(&summary.roots()[range]))
        .collect::<Vec<_>>();

    assert!(expected_range_roots.len() > 1);
    assert_eq!(summary.range_roots_for_testing(), expected_range_roots.as_slice());
    assert_eq!(summary.commitment_root(), bag_belt(&expected_range_roots));
}

#[test]
fn belt_bagging_state_uses_explicit_range_and_belt_nodes() {
    let mut belt = MmrBelt::new();
    for idx in 0..190 {
        belt.add(int_to_node(idx)).unwrap();
    }

    for (nodes, &range_root) in belt.bagging.range_nodes().iter().zip(belt.bagging.range_roots()) {
        let mut prefix = EMPTY_WORD;
        for node in nodes {
            assert_eq!(node.left, prefix);
            assert_eq!(node.root, Poseidon2::merge(&[node.left, node.right]));
            prefix = node.root;
        }
        assert_eq!(prefix, range_root);
    }

    let mut prefix = EMPTY_WORD;
    for (node, &range_root) in belt.bagging.belt_nodes().iter().zip(belt.bagging.range_roots()) {
        assert_eq!(node.left, prefix);
        assert_eq!(node.right, range_root);
        assert_eq!(node.root, Poseidon2::merge(&[node.left, node.right]));
        prefix = node.root;
    }
    assert_eq!(prefix, belt.summary().commitment_root());
}

#[test]
fn changed_range_nodes_rejects_extra_changed_mountain_in_range_prefix() {
    let old_num_leaves = 190;
    let new_num_leaves = old_num_leaves + 1;
    let roots = vec![EMPTY_WORD; shape_mountains(old_num_leaves).len()];
    let mut state = BeltBaggingState::from_roots(old_num_leaves, &roots).unwrap();

    let new_shape = shape_mountains(new_num_leaves);
    let range = shape_ranges(&new_shape)
        .into_iter()
        .find(|range| range.end - range.start > 1)
        .unwrap();
    let prefix = new_shape[range.start];
    let last = new_shape[range.end - 1];
    let old_idx =
        shape_mountain_index_for_num_leaves(old_num_leaves, prefix).expect("prefix is reused");
    let old_range_idx = shape_range_index_for_num_leaves(old_num_leaves, old_idx)
        .expect("reused prefix has an old range");
    let changed = [
        ChangedMountain::new(last.start, last.height, int_to_node(1)),
        ChangedMountain::new(prefix.start, prefix.height, int_to_node(2)),
    ];

    assert!(
        state
            .changed_range_nodes(
                old_num_leaves,
                new_num_leaves,
                range,
                &changed,
                old_range_idx,
                state.ranges.len(),
            )
            .is_err()
    );
}

#[test]
fn append_shape_in_place_rejects_extra_unchanged_changed_mountain() {
    let old_num_leaves = 3;
    let mut shape = shape_mountains(old_num_leaves);
    let unchanged = shape[0];
    let leaf = ChangedMountain::new(old_num_leaves, 0, int_to_node(old_num_leaves as u64));
    let extra = ChangedMountain {
        mountain: unchanged,
        root: int_to_node(99),
    };

    assert!(append_shape_in_place(&mut shape, old_num_leaves, &[leaf, extra]).is_err());
}

#[test]
fn belt_maintains_live_bagging_state_after_each_append() {
    let mut belt = MmrBelt::new();

    for idx in 0..512 {
        belt.add(int_to_node(idx)).unwrap();

        let rebuilt = BeltSummary::from_roots(belt.num_leaves(), &belt.peaks()).unwrap();

        assert_eq!(belt.live_range_roots_for_testing(), rebuilt.range_roots_for_testing());
        assert_eq!(belt.live_commitment_root_for_testing(), rebuilt.commitment_root());
        assert_eq!(belt.summary(), rebuilt);
    }
}

#[test]
fn belt_lazy_bagging_append_keeps_mountain_state() {
    let mut normal = MmrBelt::new();
    let mut lazy = MmrBelt::new();

    for idx in 0..512 {
        let leaf = int_to_node(idx);
        normal.add(leaf).unwrap();
        lazy.add_without_bagging_for_benchmark(leaf).unwrap();

        assert_eq!(lazy.num_leaves(), normal.num_leaves());
        assert_eq!(lazy.peaks(), normal.peaks());

        let rebuilt = BeltSummary::from_roots(lazy.num_leaves(), &lazy.peaks()).unwrap();
        assert_eq!(rebuilt, normal.summary());
    }
}

#[test]
fn belt_deferred_append_summary_matches_live_append() {
    let mut live = MmrBelt::new();
    let mut deferred = MmrBelt::new();

    for idx in 0..512 {
        let leaf = int_to_node(idx);
        live.add(leaf).unwrap();
        deferred.add_deferred(leaf).unwrap();

        assert_eq!(deferred.summary(), live.summary());
        assert_eq!(deferred.commitment_root(), live.commitment_root());
    }
}

#[test]
fn belt_live_append_after_deferred_append_refreshes_summary() {
    let mut live = MmrBelt::new();
    let mut mixed = MmrBelt::new();

    for idx in 0..128 {
        let leaf = int_to_node(idx);
        live.add(leaf).unwrap();
        if idx % 4 == 3 {
            mixed.add(leaf).unwrap();
        } else {
            mixed.add_deferred(leaf).unwrap();
        }

        assert_eq!(mixed.summary(), live.summary());
        assert_eq!(mixed.commitment_root(), live.commitment_root());
    }
}

#[test]
fn belt_lazy_bagging_append_does_not_touch_live_bagging() {
    let mut belt = MmrBelt::new();

    for idx in 0..512 {
        belt.add_without_bagging_for_benchmark(int_to_node(idx)).unwrap();

        assert_eq!(belt.last_bagging_update_hashes_for_testing(), 0);
    }
}

#[test]
fn belt_commitment_root_returns_live_bagged_root() {
    let mut belt = MmrBelt::new();

    for idx in 0..512 {
        belt.add(int_to_node(idx)).unwrap();

        let rebuilt = BeltSummary::from_roots(belt.num_leaves(), &belt.peaks()).unwrap();

        assert_eq!(belt.commitment_root(), rebuilt.commitment_root());
    }
}

#[test]
fn belt_live_bagging_update_touches_constant_commitment_hashes() {
    const MAX_INCREMENTAL_BAGGING_HASHES: usize = 4;

    let mut belt = MmrBelt::new();
    for idx in 0..4096 {
        belt.add(int_to_node(idx)).unwrap();

        assert!(
            belt.last_bagging_update_hashes_for_testing() <= MAX_INCREMENTAL_BAGGING_HASHES,
            "append {idx} touched {} commitment-layer hashes",
            belt.last_bagging_update_hashes_for_testing()
        );
    }
}

#[test]
fn belt_delta_resyncs_client_summary() {
    let total = 600usize;
    for from in [0usize, 1, 7, 64, 255, 256, 511] {
        let mut belt = MmrBelt::new();
        for idx in 0..from {
            belt.add(int_to_node(idx as u64)).unwrap();
        }
        let client_peaks = belt.peaks();

        for idx in from..total {
            belt.add(int_to_node(idx as u64)).unwrap();
        }

        let delta = belt.delta(from).unwrap();
        assert_eq!(delta.from_num_leaves(), from);
        assert_eq!(delta.to_num_leaves(), total);

        let updated = delta.apply(&client_peaks).unwrap();
        assert_eq!(updated, belt.peaks(), "resynced peaks must match (from {from})");
        assert_eq!(
            BeltSummary::from_roots(total, &updated).unwrap(),
            belt.summary(),
            "resynced commitment must match (from {from})"
        );
    }
}

#[test]
fn belt_delta_verifies_summary_transition() {
    let from = 128usize;
    let to = 191usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let delta = belt.delta(from).unwrap();

    assert!(delta.verify_transition(&old_summary, &new_summary).unwrap());
}

#[test]
fn belt_delta_rejects_wrong_transition_endpoint() {
    let from = 64usize;
    let to = 96usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let delta = belt.delta(from).unwrap();

    let mut other = MmrBelt::new();
    for idx in 0..to {
        other.add(int_to_node(10_000 + idx as u64)).unwrap();
    }
    let wrong_new_summary = other.summary();

    assert!(!delta.verify_transition(&old_summary, &wrong_new_summary).unwrap());
}

#[test]
fn belt_delta_rejects_mutated_tail_peak() {
    let from = 128usize;
    let to = 191usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let mut delta = belt.delta(from).unwrap();
    delta.new_tail_peaks[0] = int_to_node(999_999);

    assert!(!delta.verify_transition(&old_summary, &new_summary).unwrap());
}

#[test]
fn belt_delta_verify_rejects_padded_auth_nodes() {
    let from = 128usize;
    let to = 191usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let delta = belt.delta(from).unwrap();
    assert!(delta.verify_transition(&old_summary, &new_summary).unwrap());

    // Padding a valid delta with an auth node outside the required climb set must be rejected, so a
    // peer cannot inflate a sync delta with bogus data.
    let mut padded_auth = delta.merge_auth_nodes().collect::<Vec<_>>();
    padded_auth.push(((usize::MAX, 0), int_to_node(123_456)));
    let padded = MmrBeltDelta::from_parts(
        delta.from_num_leaves(),
        delta.to_num_leaves(),
        delta.new_tail_peaks().to_vec(),
        padded_auth,
    )
    .unwrap();

    assert!(!padded.verify_transition(&old_summary, &new_summary).unwrap());
}

#[test]
fn belt_constructors_reject_oversized_num_leaves() {
    // `shape_mountains` computes `num_leaves + 1`; oversized counts must error, not panic.
    assert!(BeltSummary::from_roots(usize::MAX, &[]).is_err());
    assert!(PartialMmrBelt::from_peaks(usize::MAX, Vec::new()).is_err());
    assert!(MmrBeltDelta::from_parts(0, usize::MAX, Vec::new(), core::iter::empty()).is_err());
}

#[test]
fn partial_belt_apply_is_transactional_on_missing_auth() {
    let from = 200usize;
    let to = 260usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }

    let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    for pos in 0..from {
        partial.track(&belt.open(pos).unwrap()).unwrap();
    }

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }

    let mut delta = belt.delta(from).unwrap();
    assert!(delta.num_merge_auth_nodes() > 0, "increment must merge some tracked mountains");
    // Drop the auth nodes a now-merged tracked leaf needs, so the update cannot complete.
    delta.merge_auth.clear();

    let before = partial.clone();
    assert!(partial.apply(&delta).is_err());
    // The failure must leave the view untouched — no partial advance of num_leaves/peaks/tracked.
    assert_eq!(partial, before);
}

#[test]
fn belt_delta_rejects_wrong_absorbed_old_summary_root() {
    let from = 128usize;
    let to = 191usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();
    let common = common_peak_prefix_len(from, to);
    assert!(common < old_summary.roots().len());

    let mut wrong_old_roots = old_summary.roots().to_vec();
    wrong_old_roots[common] = int_to_node(999_999);
    let wrong_old_summary = BeltSummary::from_roots(from, &wrong_old_roots).unwrap();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let delta = belt.delta(from).unwrap();

    assert!(!delta.verify_transition(&wrong_old_summary, &new_summary).unwrap());
}

#[test]
fn belt_delta_transition_requires_merge_auth_for_absorbed_old_roots() {
    let from = 200usize;
    let to = 260usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let mut delta = belt.delta(from).unwrap();
    assert!(common_peak_prefix_len(from, to) < old_summary.roots().len());
    delta.merge_auth.clear();

    assert!(delta.verify_transition(&old_summary, &new_summary).is_err());
}

#[test]
fn belt_delta_rejects_forged_merge_auth_value() {
    let from = 200usize;
    let to = 260usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();

    let mut delta = belt.delta(from).unwrap();
    assert!(delta.verify_transition(&old_summary, &new_summary).unwrap());

    let key = *delta.merge_auth.keys().next().expect("absorbed roots need merge-auth nodes");
    delta.merge_auth.insert(key, int_to_node(999_999));

    assert!(!delta.verify_transition(&old_summary, &new_summary).unwrap());
}

#[test]
fn belt_zero_and_single_leaf_summaries() {
    let empty = MmrBelt::new();
    let empty_summary = empty.summary();
    assert_eq!(empty_summary.num_leaves(), 0);
    assert!(empty_summary.roots().is_empty());
    assert_eq!(empty_summary.commitment_root(), EMPTY_WORD);
    assert_eq!(
        empty_summary,
        BeltSummary::from_roots(0, &[]).unwrap(),
        "live empty summary must match a from-scratch rebuild"
    );

    let mut single = MmrBelt::new();
    single.add(int_to_node(42)).unwrap();
    let single_summary = single.summary();
    assert_eq!(single_summary.num_leaves(), 1);
    assert_eq!(single_summary, BeltSummary::from_roots(1, &single.peaks()).unwrap());

    let proof = single.open(0).unwrap();
    assert!(proof.verify(&single_summary));
}

#[test]
fn belt_delta_from_same_leaf_count_is_noop() {
    let mut belt = MmrBelt::new();
    for idx in 0..50 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let summary = belt.summary();

    let delta = belt.delta(belt.num_leaves()).unwrap();
    assert!(delta.verify_transition(&summary, &summary).unwrap());
    assert_eq!(delta.apply(summary.roots()).unwrap(), summary.roots());

    let empty = MmrBelt::new();
    let empty_summary = empty.summary();
    let empty_delta = empty.delta(0).unwrap();
    assert!(empty_delta.verify_transition(&empty_summary, &empty_summary).unwrap());
    assert!(empty_delta.apply(empty_summary.roots()).unwrap().is_empty());
}

#[test]
fn belt_delta_is_logarithmic_in_increment() {
    let mut belt = MmrBelt::new();
    for idx in 0..100_000u64 {
        belt.add(int_to_node(idx)).unwrap();
    }

    for k in [1usize, 2, 10, 100, 1000] {
        let delta = belt.delta(100_000 - k).unwrap();
        let bound = 2 * (usize::BITS - k.leading_zeros()) as usize + 4;
        assert!(
            delta.new_tail_peaks().len() <= bound,
            "k={k}: tail {} exceeded bound {bound}",
            delta.new_tail_peaks().len()
        );
    }
}

#[test]
fn belt_delta_rejects_future_origin() {
    let mut belt = MmrBelt::new();
    for idx in 0..10 {
        belt.add(int_to_node(idx)).unwrap();
    }
    assert!(belt.delta(11).is_err());
}

#[test]
fn partial_belt_tracks_and_opens_like_full_belt() {
    let mut belt = MmrBelt::new();
    let leaves = (0..50u64).map(int_to_node).collect::<Vec<_>>();
    for leaf in leaves.iter().copied() {
        belt.add(leaf).unwrap();
    }

    let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    assert_eq!(partial.summary(), belt.summary());

    for position in 0..leaves.len() {
        partial.track(&belt.open(position).unwrap()).unwrap();
    }
    assert_eq!(partial.num_tracked(), leaves.len());

    for (position, leaf) in leaves.iter().copied().enumerate() {
        let proof = partial.open(position).unwrap().unwrap();
        assert_eq!(proof, belt.open(position).unwrap());
        assert_eq!(partial.get(position), Some(leaf));
        assert!(proof.verify(&partial.summary()));
    }
}

#[test]
fn partial_belt_from_peaks_rejects_wrong_count() {
    let mut belt = MmrBelt::new();
    for idx in 0..7 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let mut peaks = belt.peaks();
    peaks.pop();
    assert!(PartialMmrBelt::from_peaks(belt.num_leaves(), peaks).is_err());
}

#[test]
fn partial_belt_track_rejects_unauthenticated_proof() {
    let mut belt = MmrBelt::new();
    for idx in 0..16 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();

    let mut proof = belt.open(5).unwrap();
    proof.set_leaf_for_testing(int_to_node(999));
    assert!(partial.track(&proof).is_err());
    assert!(!partial.is_tracked(5));
}

#[test]
fn partial_belt_apply_extends_all_tracks_in_place() {
    let from = 200usize;
    let to = 260usize;

    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }

    let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    for position in 0..from {
        partial.track(&belt.open(position).unwrap()).unwrap();
    }

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }

    partial.apply(&belt.delta(from).unwrap()).unwrap();

    assert_eq!(partial.num_leaves(), to);
    assert_eq!(partial.summary(), belt.summary());
    assert_eq!(partial.num_tracked(), from);

    for position in 0..from {
        assert!(partial.is_tracked(position), "leaf {position} must still be tracked");
        assert_eq!(partial.open(position).unwrap().unwrap(), belt.open(position).unwrap());
    }
}

#[test]
fn partial_belt_apply_extends_across_many_increments() {
    let mut belt = MmrBelt::new();
    for idx in 0..40u64 {
        belt.add(int_to_node(idx)).unwrap();
    }

    let mut partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    let tracked = [0usize, 1, 17, 38, 39];
    for &position in &tracked {
        partial.track(&belt.open(position).unwrap()).unwrap();
    }

    let mut next = 40u64;
    for _ in 0..30 {
        let from = belt.num_leaves();
        for _ in 0..7 {
            belt.add(int_to_node(next)).unwrap();
            next += 1;
        }
        partial.apply(&belt.delta(from).unwrap()).unwrap();

        assert_eq!(partial.summary(), belt.summary());
        for &position in &tracked {
            assert_eq!(partial.open(position).unwrap().unwrap(), belt.open(position).unwrap());
        }
    }
}

#[test]
fn partial_belt_protocol_model_resyncs_after_offline_increment() {
    let from = 128usize;
    let to = 191usize;
    let leaves = (0..to as u64).map(int_to_node).collect::<Vec<_>>();

    let mut full_node = MmrBelt::new();
    for &leaf in &leaves[..from] {
        full_node.add(leaf).unwrap();
    }

    let mut client = PartialMmrBelt::from_peaks(full_node.num_leaves(), full_node.peaks()).unwrap();
    for &position in &[0usize, 1, 7, 63, 64, 100, 127] {
        client.track(&full_node.open(position).unwrap()).unwrap();
    }
    assert_eq!(client.summary(), full_node.summary());

    for &leaf in &leaves[from..to] {
        full_node.add(leaf).unwrap();
    }
    let server_delta = full_node.delta(from).unwrap();

    assert_ne!(client.summary(), full_node.summary());
    client.apply_verified(&server_delta, &full_node.summary()).unwrap();
    assert_eq!(client.summary(), full_node.summary());

    for &position in &[0usize, 1, 7, 63, 64, 100, 127] {
        let client_proof = client.open(position).unwrap().unwrap();
        assert!(client_proof.verify(&client.summary()));
        assert_eq!(client_proof, full_node.open(position).unwrap());
        assert_eq!(client.get(position), Some(leaves[position]));
    }

    let newest_position = to - 1;
    client.track(&full_node.open(newest_position).unwrap()).unwrap();
    assert_eq!(client.get(newest_position), Some(leaves[newest_position]));
    assert!(client.open(newest_position).unwrap().unwrap().verify(&client.summary()));
}

#[test]
fn belt_delta_and_summary_verify_sync_response_transition() {
    let from = 128usize;
    let to = 191usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let old_summary = belt.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }

    let belt_delta = belt.delta(from).unwrap();
    let belt_summary = belt.summary();
    assert_eq!(belt_delta.from_num_leaves(), from);
    assert_eq!(belt_delta.to_num_leaves(), to);
    assert!(belt_delta.verify_transition(&old_summary, &belt_summary).unwrap());
}

#[test]
fn partial_belt_apply_verified_resyncs_sync_response() {
    let from = 128usize;
    let to = 191usize;
    let leaves = (0..to as u64).map(int_to_node).collect::<Vec<_>>();

    let mut full_node = MmrBelt::new();
    for &leaf in &leaves[..from] {
        full_node.add(leaf).unwrap();
    }
    let mut client = PartialMmrBelt::from_peaks(full_node.num_leaves(), full_node.peaks()).unwrap();
    client.track(&full_node.open(from - 1).unwrap()).unwrap();

    for &leaf in &leaves[from..to] {
        full_node.add(leaf).unwrap();
    }
    let belt_delta = full_node.delta(from).unwrap();
    let belt_summary = full_node.summary();

    client.apply_verified(&belt_delta, &belt_summary).unwrap();
    assert_eq!(client.summary(), full_node.summary());
    assert_eq!(client.open(from - 1).unwrap().unwrap(), full_node.open(from - 1).unwrap());
}

#[test]
fn belt_delta_from_parts_reconstructs_sync_response() {
    let from = 128usize;
    let to = 191usize;
    let leaves = (0..to as u64).map(int_to_node).collect::<Vec<_>>();

    let mut full_node = MmrBelt::new();
    for &leaf in &leaves[..from] {
        full_node.add(leaf).unwrap();
    }
    let old_summary = full_node.summary();
    let mut client = PartialMmrBelt::from_peaks(full_node.num_leaves(), full_node.peaks()).unwrap();
    client.track(&full_node.open(from - 1).unwrap()).unwrap();

    for &leaf in &leaves[from..to] {
        full_node.add(leaf).unwrap();
    }

    let server_delta = full_node.delta(from).unwrap();
    let server_summary = full_node.summary();
    let belt_delta = MmrBeltDelta::from_parts(
        server_delta.from_num_leaves(),
        server_delta.to_num_leaves(),
        server_delta.new_tail_peaks().to_vec(),
        server_delta.merge_auth_nodes(),
    )
    .unwrap();
    let summary_roots = server_summary.roots().to_vec();
    let belt_summary =
        BeltSummary::from_roots(server_summary.num_leaves(), &summary_roots).unwrap();

    assert_eq!(belt_delta, server_delta);
    assert_eq!(belt_summary, server_summary);
    assert!(belt_delta.verify_transition(&old_summary, &belt_summary).unwrap());

    client.apply_verified(&belt_delta, &belt_summary).unwrap();
    assert_eq!(client.summary(), full_node.summary());
    assert_eq!(client.open(from - 1).unwrap().unwrap(), full_node.open(from - 1).unwrap());
}

#[test]
fn belt_delta_from_parts_rejects_invalid_tail_shape() {
    let mut belt = MmrBelt::new();
    for idx in 0..191 {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let server_delta = belt.delta(128).unwrap();

    assert!(
        MmrBeltDelta::from_parts(
            server_delta.from_num_leaves(),
            server_delta.to_num_leaves(),
            vec![],
            server_delta.merge_auth_nodes()
        )
        .is_err()
    );
}

#[test]
fn partial_belt_apply_verified_rejects_wrong_new_summary() {
    let from = 64usize;
    let to = 96usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let mut client = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    client.track(&belt.open(from - 1).unwrap()).unwrap();
    let old_summary = client.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let delta = belt.delta(from).unwrap();

    let mut other = MmrBelt::new();
    for idx in 0..to {
        other.add(int_to_node(10_000 + idx as u64)).unwrap();
    }
    let wrong_new_summary = other.summary();

    assert!(client.apply_verified(&delta, &wrong_new_summary).is_err());
    assert_eq!(client.summary(), old_summary);
}

#[test]
fn partial_belt_apply_verified_rejects_missing_merge_auth_without_mutating() {
    let from = 200usize;
    let to = 260usize;
    let mut belt = MmrBelt::new();
    for idx in 0..from {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let mut client = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    client.track(&belt.open(from - 1).unwrap()).unwrap();
    let old_summary = client.summary();

    for idx in from..to {
        belt.add(int_to_node(idx as u64)).unwrap();
    }
    let new_summary = belt.summary();
    let mut delta = belt.delta(from).unwrap();
    delta.merge_auth.clear();

    assert!(client.apply_verified(&delta, &new_summary).is_err());
    assert_eq!(client.summary(), old_summary);
}

#[test]
fn partial_belt_delta_merge_auth_is_polylogarithmic() {
    let mut belt = MmrBelt::new();
    for idx in 0..100_000u64 {
        belt.add(int_to_node(idx)).unwrap();
    }

    for k in [1usize, 2, 16, 256, 4096] {
        let delta = belt.delta(100_000 - k).unwrap();
        let log_k = (usize::BITS - k.leading_zeros()) as usize;
        let bound = 4 * log_k * log_k + 8;
        assert!(
            delta.num_merge_auth_nodes() <= bound,
            "k={k}: {} auth nodes exceeded bound {bound}",
            delta.num_merge_auth_nodes()
        );
    }
}

// Gated behind `std` so the no-std test build (which has no `println!`) still compiles.
#[cfg(feature = "std")]
#[test]
#[ignore = "prints deterministic MMB issue measurement tables"]
fn mmb_issue_measurement_report() {
    use std::println;

    const STORAGE_SIZES: &[usize] = &[1_000, 65_536, 100_000];
    const PROOF_SIZE: usize = 65_536;
    const DELTA_SIZE: usize = 100_000;
    const RECENCIES: &[usize] = &[1, 2, 4, 8, 16, 64, 512, 4_096, 16_384, 65_536];
    const GAPS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 512, 4_096, 16_384, 65_536];

    println!("# MMB issue measurement report");
    println!();
    println!("## Storage shape");
    println!(
        "| leaves | MMR nodes | MMR peaks | Frontier peaks | Belt hash slots | Belt live hashes | Belt mountains | Belt ranges | Belt range nodes | Belt belt nodes |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for &size in STORAGE_SIZES {
        let (mmr, belt) = build_mmr_and_belt(size);
        let frontier = mmr.frontier();
        let range_nodes = belt.bagging.range_nodes().iter().map(Vec::len).sum::<usize>();
        println!(
            "| {size} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            mmr.forest().num_nodes(),
            mmr.peaks().num_peaks(),
            frontier.num_peaks(),
            belt.hashes.slot_count(),
            belt.hashes.live_count(),
            belt.ordered_mountains().len(),
            belt.bagging.range_roots().len(),
            range_nodes,
            belt.bagging.belt_nodes().len()
        );
    }

    let (mmr, belt) = build_mmr_and_belt(PROOF_SIZE);
    let summary = belt.summary();
    println!();
    println!("## Proof nodes by recency");
    println!("n = {PROOF_SIZE}");
    println!("| recency k | position | MMR path nodes | Frontier proof nodes | Belt proof nodes |");
    println!("|---:|---:|---:|---:|---:|");
    for &recency in RECENCIES {
        if recency > PROOF_SIZE {
            continue;
        }
        let position = PROOF_SIZE - recency;
        let mmr_nodes = mmr.open(position).unwrap().merkle_path().nodes().len();
        let frontier_proof_nodes = mmr.open_frontier(position).unwrap().path.nodes().len();
        let belt_proof = belt.open(position).unwrap();
        assert!(belt_proof.verify(&summary));
        println!(
            "| {recency} | {position} | {mmr_nodes} | {frontier_proof_nodes} | {} |",
            belt_proof.nodes.len()
        );
    }

    let (mmr, belt) = build_mmr_and_belt(DELTA_SIZE);
    println!();
    println!("## Delta words by offline gap");
    println!("target n = {DELTA_SIZE}");
    println!(
        "| gap k | from leaves | Current MMR delta words | Belt tail roots | Belt merge auth nodes | Belt total words |"
    );
    println!("|---:|---:|---:|---:|---:|---:|");
    for &gap in GAPS {
        if gap > DELTA_SIZE {
            continue;
        }
        let from = DELTA_SIZE - gap;
        let mmr_delta = mmr
            .get_delta(crate::merkle::mmr::Forest::new(from).unwrap(), mmr.forest())
            .unwrap();
        let belt_delta = belt.delta(from).unwrap();
        let tail_roots = belt_delta.new_tail_peaks().len();
        let merge_auth = belt_delta.num_merge_auth_nodes();
        println!(
            "| {gap} | {from} | {} | {tail_roots} | {merge_auth} | {} |",
            mmr_delta.data.len(),
            tail_roots + merge_auth
        );
    }
}

#[cfg(feature = "std")]
fn build_mmr_and_belt(size: usize) -> (crate::merkle::mmr::Mmr, MmrBelt) {
    let leaves = (0..size as u64).map(int_to_node).collect::<Vec<_>>();
    let mmr = crate::merkle::mmr::Mmr::try_from_iter(leaves.iter().copied()).unwrap();
    let mut belt = MmrBelt::new();
    for leaf in leaves {
        belt.add(leaf).unwrap();
    }
    (mmr, belt)
}

#[test]
fn partial_belt_open_untracked_returns_none() {
    let mut belt = MmrBelt::new();
    for idx in 0..16 {
        belt.add(int_to_node(idx)).unwrap();
    }
    let partial = PartialMmrBelt::from_peaks(belt.num_leaves(), belt.peaks()).unwrap();
    assert!(partial.open(3).unwrap().is_none());
}

#[test]
fn belt_height_sequences_match_paper() {
    // Golden S_n sequences from arXiv:2511.13582, §3.1 and Figures 5/7/9.
    let golden: [(usize, &[usize]); 4] = [
        (9, &[2, 2, 0]),
        (10, &[2, 2, 1]),
        (11, &[3, 1, 0]),
        (1337, &[9, 9, 7, 6, 6, 5, 4, 2, 2, 0]),
    ];

    for (num_leaves, expected) in golden {
        assert_eq!(shape_heights(num_leaves), expected, "shape S_{num_leaves}");

        let mut belt = MmrBelt::new();
        for idx in 0..num_leaves {
            belt.add(int_to_node(idx as u64)).unwrap();
        }
        assert_eq!(belt.mountain_heights(), expected, "live S_{num_leaves}");
    }
}

#[test]
fn belt_merge_peak_lands_in_last_two_ranges() {
    // Lemma 16.
    for num_leaves in 2..4096usize {
        if (num_leaves + 1).is_power_of_two() {
            continue;
        }

        let shape = shape_mountains(num_leaves);
        let merge_idx = shape.len() - 1 - (num_leaves + 1).trailing_zeros() as usize;

        let ranges = shape_ranges(&shape);
        let range_idx = ranges
            .iter()
            .position(|range| range.contains(&merge_idx))
            .expect("merge peak must lie in a range");

        assert_eq!(
            ranges[range_idx].end,
            merge_idx + 1,
            "n={num_leaves}: merge peak must sit at the right end of its range"
        );
        assert!(
            range_idx + 2 >= ranges.len(),
            "n={num_leaves}: merge peak must be in the rightmost or second-rightmost range"
        );
    }
}
