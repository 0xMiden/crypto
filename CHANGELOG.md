## 0.15.0 (TBD)


## 0.14.0 (2025-03-15)

- Added parallel implementation of `Smt::compute_mutations` with better performance (#365).
- Implemented parallel leaf hashing in `Smt::process_sorted_pairs_to_leaves` (#365).
- Removed duplicated check in RpoFalcon512 verification (#368).
- [BREAKING] Updated Winterfell dependency to v0.12 (#374).
- Added debug-only duplicate column check in `build_subtree` (#378).
- Filter out empty values in concurrent version of `Smt::with_entries` to fix a panic (#383).
- Added property-based testing (proptest) and fuzzing for `Smt::with_entries` and `Smt::compute_mutations` (#385).
- Sort keys in a leaf in the concurrent implementation of `Smt::with_entries`, ensuring consistency with the sequential version (#385).
- Skip unchanged leaves in the concurrent implementation of `Smt::compute_mutations` (#385).
- Add range checks to `ntru_gen` for Falcon DSA (#391).
- Optimized duplicate key detection in `Smt::with_entries_concurrent` (#395).
- [BREAKING] Moved `rand` to version `0.9` removing the `try_fill_bytes` method (#398).
- [BREAKING] Increment minimum supported Rust version to 1.85 (#399).
- Added `SparseMerklePath`, a compact representation of `MerklePath` which compacts empty nodes into a bitmask (#389).

## 0.13.3 (2025-02-18)

- Implement `PartialSmt` (#372, #381).
- Fix panic in `PartialMmr::untrack` (#382).

## 0.13.2 (2025-01-24)

- Made `InnerNode` and `NodeMutation` public. Implemented (de)serialization of `LeafIndex` (#367).

## 0.13.1 (2024-12-26)

- Generate reverse mutations set on applying of mutations set, implemented serialization of `MutationsSet` (#355).

## 0.13.0 (2024-11-24)

- Fixed a bug in the implementation of `draw_integers` for `RpoRandomCoin` (#343).
- [BREAKING] Refactor error messages and use `thiserror` to derive errors (#344).
- [BREAKING] Updated Winterfell dependency to v0.11 (#346).
- Added support for hashmaps in `Smt` and `SimpleSmt` which gives up to 10x boost in some operations (#363).

## 0.12.0 (2024-10-30)

- [BREAKING] Updated Winterfell dependency to v0.10 (#338).
- Added parallel implementation of `Smt::with_entries()` with significantly better performance when the `concurrent` feature is enabled (#341).

## 0.11.0 (2024-10-17)

- [BREAKING]: renamed `Mmr::open()` into `Mmr::open_at()` and `Mmr::peaks()` into `Mmr::peaks_at()` (#234).
- Added `Mmr::open()` and `Mmr::peaks()` which rely on `Mmr::open_at()` and `Mmr::peaks()` respectively (#234).
- Standardized CI and Makefile across Miden repos (#323).
- Added `Smt::compute_mutations()` and `Smt::apply_mutations()` for validation-checked insertions (#327).
- Changed padding rule for RPO/RPX hash functions (#318).
- [BREAKING] Changed return value of the `Mmr::verify()` and `MerklePath::verify()` from `bool` to `Result<>` (#335).
- Added `is_empty()` functions to the `SimpleSmt` and `Smt` structures. Added `EMPTY_ROOT` constant to the `SparseMerkleTree` trait (#337).

## 0.10.3 (2024-09-25)

- Implement `get_size_hint` for `Smt` (#331).

## 0.10.2 (2024-09-25)

- Implement `get_size_hint` for `RpoDigest` and `RpxDigest` and expose constants for their serialized size (#330).

## 0.10.1 (2024-09-13)

- Added `Serializable` and `Deserializable` implementations for `PartialMmr` and `InOrderIndex` (#329).

## 0.10.0 (2024-08-06)

- Added more `RpoDigest` and `RpxDigest` conversions (#311).
- [BREAKING] Migrated to Winterfell v0.9 (#315).
- Fixed encoding of Falcon secret key (#319).

## 0.9.3 (2024-04-24)

- Added `RpxRandomCoin` struct (#307).

## 0.9.2 (2024-04-21)

- Implemented serialization for the `Smt` struct (#304).
- Fixed a bug in Falcon signature generation (#305).

## 0.9.1 (2024-04-02)

- Added `num_leaves()` method to `SimpleSmt` (#302).

## 0.9.0 (2024-03-24)

- [BREAKING] Removed deprecated re-exports from liballoc/libstd (#290).
- [BREAKING] Refactored RpoFalcon512 signature to work with pure Rust (#285).
- [BREAKING] Added `RngCore` as supertrait for `FeltRng` (#299).

# 0.8.4 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (`vec` and `format` macros).

# 0.8.3 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (#292).

# 0.8.2 (2024-03-17)

- Updated `no-std` approach to be in sync with winterfell v0.8.3 release (#290).

## 0.8.1 (2024-02-21)

- Fixed clippy warnings (#280)

## 0.8.0 (2024-02-14)

- Implemented the `PartialMmr` data structure (#195).
- Implemented RPX hash function (#201).
- Added `FeltRng` and `RpoRandomCoin` (#237).
- Accelerated RPO/RPX hash functions using AVX512 instructions (#234).
- Added `inner_nodes()` method to `PartialMmr` (#238).
- Improved `PartialMmr::apply_delta()` (#242).
- Refactored `SimpleSmt` struct (#245).
- Replaced `TieredSmt` struct with `Smt` struct (#254, #277).
- Updated Winterfell dependency to v0.8 (#275).

## 0.7.1 (2023-10-10)

- Fixed RPO Falcon signature build on Windows.

## 0.7.0 (2023-10-05)

- Replaced `MerklePathSet` with `PartialMerkleTree` (#165).
- Implemented clearing of nodes in `TieredSmt` (#173).
- Added ability to generate inclusion proofs for `TieredSmt` (#174).
- Implemented Falcon DSA (#179).
- Added conditional `serde`` support for various structs (#180).
- Implemented benchmarking for `TieredSmt` (#182).
- Added more leaf traversal methods for `MerkleStore` (#185).
- Added SVE acceleration for RPO hash function (#189).

## 0.6.0 (2023-06-25)

- [BREAKING] Added support for recording capabilities for `MerkleStore` (#162).
- [BREAKING] Refactored Merkle struct APIs to use `RpoDigest` instead of `Word` (#157).
- Added initial implementation of `PartialMerkleTree` (#156).

## 0.5.0 (2023-05-26)

- Implemented `TieredSmt` (#152, #153).
- Implemented ability to extract a subset of a `MerkleStore` (#151).
- Cleaned up `SimpleSmt` interface (#149).
- Decoupled hashing and padding of peaks in `Mmr` (#148).
- Added `inner_nodes()` to `MerkleStore` (#146).

## 0.4.0 (2023-04-21)

- Exported `MmrProof` from the crate (#137).
- Allowed merging of leaves in `MerkleStore` (#138).
- [BREAKING] Refactored how existing data structures are added to `MerkleStore` (#139).

## 0.3.0 (2023-04-08)

- Added `depth` parameter to SMT constructors in `MerkleStore` (#115).
- Optimized MMR peak hashing for Miden VM (#120).
- Added `get_leaf_depth` method to `MerkleStore` (#119).
- Added inner node iterators to `MerkleTree`, `SimpleSmt`, and `Mmr` (#117, #118, #121).

## 0.2.0 (2023-03-24)

- Implemented `Mmr` and related structs (#67).
- Implemented `MerkleStore` (#93, #94, #95, #107 #112).
- Added benchmarks for `MerkleStore` vs. other structs (#97).
- Added Merkle path containers (#99).
- Fixed depth handling in `MerklePathSet` (#110).
- Updated Winterfell dependency to v0.6.

## 0.1.4 (2023-02-22)

- Re-export winter-crypto Hasher, Digest & ElementHasher (#72)

## 0.1.3 (2023-02-20)

- Updated Winterfell dependency to v0.5.1 (#68)

## 0.1.2 (2023-02-17)

- Fixed `Rpo256::hash` pad that was panicking on input (#44)
- Added `MerklePath` wrapper to encapsulate Merkle opening verification and root computation (#53)
- Added `NodeIndex` Merkle wrapper to encapsulate Merkle tree traversal and mappings (#54)

## 0.1.1 (2023-02-06)

- Introduced `merge_in_domain` for the RPO hash function, to allow using a specified domain value in the second capacity register when hashing two digests together.
- Added a simple sparse Merkle tree implementation.
- Added re-exports of Winterfell RandomCoin and RandomCoinError.

## 0.1.0 (2022-12-02)

- Initial release on crates.io containing the cryptographic primitives used in Miden VM and the Miden Rollup.
- Hash module with the BLAKE3 and Rescue Prime Optimized hash functions.
  - BLAKE3 is implemented with 256-bit, 192-bit, or 160-bit output.
  - RPO is implemented with 256-bit output.
- Merkle module, with a set of data structures related to Merkle trees, implemented using the RPO hash function.
