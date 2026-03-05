#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    merkle::MerkleStore,
    utils::Deserializable,
};

fuzz_target!(|data: &[u8]| {
    let _ = MerkleStore::read_from_bytes(data);
});
