#![no_main]

use core::mem::size_of;

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    merkle::smt::{LeafIndex, PartialSmt, SmtLeaf, UniqueNodes},
    utils::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    // Exercise the public deserializer directly, matching the other serde fuzz targets.
    let _ = PartialSmt::read_from_bytes(data);
    let _ = Vec::<PartialSmt>::read_from_bytes(data);
    let _ = Option::<PartialSmt>::read_from_bytes(data);
    let _ = <[PartialSmt; 1]>::read_from_bytes(data);

    // Keep the fuzzer close to parse-valid compact PartialSmt encodings so it can reach
    // reconstruction paths guarded by structural invariants rather than byte parsing.
    if let Some(leaf_index) = leaf_index_from_prefix(data) {
        let unique_nodes = UniqueNodes {
            leaves: vec![(
                leaf_index,
                SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_index)),
            )],
            ..UniqueNodes::empty()
        };

        let _ = PartialSmt::read_from_bytes(&unique_nodes.to_bytes());
    }
});

fn leaf_index_from_prefix(data: &[u8]) -> Option<u64> {
    let prefix = data.get(..size_of::<u64>())?;
    Some(u64::from_le_bytes(prefix.try_into().expect("prefix length is checked")))
}
