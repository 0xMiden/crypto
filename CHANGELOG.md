## 0.19.0 (TBD)

- [BREAKING] Replace underlying field implementation with Plonky3 backend.

## 0.18.0 (2025-10-27)

- [BREAKING] Incremented MSRV to 1.90.
- Added implementation of sealed box primitive ([#514](https://github.com/0xMiden/crypto/pull/514)).
- [BREAKING] Added DSA (EdDSA25519) and ECDH (X25519) using Curve25519 ([#537](https://github.com/0xMiden/crypto/pull/537)).
- Added `AVX512` acceleration for RPO and RPX hash functions, including parallelized E-rounds for RPX ([#551](https://github.com/0xMiden/crypto/pull/551)).
- Added `SmtForest` structure ([#563](https://github.com/0xMiden/crypto/pull/563)).
- Added `HasherExt` trait to provide ability to hash using an iterator of slices. ([#565](https://github.com/0xMiden/crypto/pull/565)).
- [BREAKING] Refactor `PartialSmt` to be constructible from a root ([#569](https://github.com/0xMiden/crypto/pull/569)).
- Added `Debug`, `Clone`, `Eq` and `PartialEq` derives to secret key structs for DSA-s ([#589](https://github.com/0xMiden/crypto/pull/589)).
- Added zeroization of secret key structs for DSA-s ([#590](https://github.com/0xMiden/crypto/pull/590)).
- Added `SmtProof::authenticated_nodes()` delegating to `SparseMerklePath::authenticated_nodes` ([#585](https://github.com/0xMiden/crypto/pull/585)).
- Refactored `LargeSmt` to use flat `Vec<Word>` layout for in-memory nodes ([#591](https://github.com/0xMiden/crypto/pull/594)).
- Added benchmarks for ECDSA-k256 and EdDSA-25519 ([#598](https://github.com/0xMiden/crypto/pull/598)).

## 0.17.1 (2025-10-10)

- Support ECDSA signing/verifying with prehashed messages ([#573](https://github.com/0xMiden/crypto/pull/573)).

## 0.17.0 (2025-09-12)

- Added `LargeSmt`, SMT backed by RocksDB ([#438](https://github.com/0xMiden/miden-crypto/pull/438)).
- Added ECDSA and ECDH modules ([#475](https://github.com/0xMiden/crypto/pull/475)).
- added arithmetization oriented authenticated encryption with associated data (AEAD) scheme ([#480](https://github.com/0xMiden/crypto/pull/480)).
- Added XChaCha20-Poly1305 AEAD scheme ([#484](https://github.com/0xMiden/crypto/pull/484)).
- [BREAKING] `SmtLeaf::entries()` now returns a slice ([#521](https://github.com/0xMiden/crypto/pull/521)).

## 0.16.1 (2025-08-21)

- Fix broken imports in CPU-specific `rescue` implementations (AVX2, SVE) ([#492](https://github.com/0xMiden/crypto/pull/492/)).
- Added `{Smt,PartialSmt}::inner_node_indices` to make inner nodes accessible ([#494](https://github.com/0xMiden/crypto/pull/494)).
- Added various benchmarks & related bench utilities ([#503](https://github.com/0xMiden/crypto/pull/503))

## 0.16.0 (2025-08-15)

- [BREAKING] Incremented MSRV to 1.88.
- Added implementation of Poseidon2 hash function ([#429](https://github.com/0xMiden/crypto/issues/429)).
- [BREAKING] Make Falcon DSA deterministic ([#436](https://github.com/0xMiden/crypto/pull/436)).
- [BREAKING] Remove generics from `MerkleStore` and remove `KvMap` and `RecordingMap` ([#442](https://github.com/0xMiden/crypto/issues/442)).
- [BREAKING] Rename `smt_hashmaps` feature to `hashmaps` ([#442](https://github.com/0xMiden/crypto/issues/442)).
- [BREAKING] Refactor `parse_hex_string_as_word()` to `Word::parse()` ([#450](https://github.com/0xMiden/crypto/issues/450)).
- `Smt.insert_inner_nodes` does not store empty subtrees ([#452](https://github.com/0xMiden/crypto/pull/452)).
- Optimized `Smt::num_entries()` ([#455](https://github.com/0xMiden/crypto/pull/455)).
- [BREAKING] Disallow leaves with more than 2^16 entries ([#455](https://github.com/0xMiden/crypto/pull/455), [#462](https://github.com/0xMiden/crypto/pull/462)).
-  Add ECDSA over secp256k1 curve ([#475](https://github.com/0xMiden/crypto/pull/475)).
- [BREAKING] Modified the public key in Falcon DSA to be the polynomial instead of the commitment ([#460](https://github.com/0xMiden/crypto/pull/460)).
- [BREAKING] Use `SparseMerklePath` in SMT proofs for better memory efficiency ([#477](https://github.com/0xMiden/crypto/pull/477)).
- [BREAKING] Rename `SparseValuePath` to `SimpleSmtProof` ([#477](https://github.com/0xMiden/crypto/pull/477)).
- Validate `NodeIndex` depth ([#482](https://github.com/0xMiden/crypto/pull/482)).
- [BREAKING] Rename `ValuePath` to `MerkleProof` ([#483](https://github.com/0xMiden/crypto/pull/483)).
- Added an implementation of Keccak256 hash function ([#487](https://github.com/0xMiden/crypto/pull/487)).

# 0.15.9 (2025-07-24)

- Added serialization for `Mmr` and `Forest` ([#466](https://github.com/0xMiden/crypto/pull/466)).

# 0.15.8 (2025-07-21)

- Added constructor for `SparseMerklePath` that accepts a bitmask and a vector of nodes ([#457](https://github.com/0xMiden/crypto/pull/457)).

## 0.15.7 (2025-07-18)

- Fix empty SMT serialization check in testing mode ([#456](https://github.com/0xMiden/crypto/pull/456)).

## 0.15.6 (2025-07-15)

- Added conversions and serialization for `PartialSmt` ([#451](https://github.com/0xMiden/crypto/pull/451/), [#453](https://github.com/0xMiden/crypto/pull/453/)).

## 0.15.5 (2025-07-10)

- Added `empty()` and `is_empty()` methods to `Word`.

## 0.15.4 (2025-07-07)

- Implemented `LexicographicWord` struct ([#443](https://github.com/0xMiden/crypto/pull/443/)).
- Added `SequentialCommit` trait ([#443](https://github.com/0xMiden/crypto/pull/443/)).

## 0.15.3 (2025-06-18)

- Fixed conversion error from a slice of bytes into `Word`.
- Added from element slice into `Word` conversion.

## 0.15.2 (2025-06-18)

- Added `to_vec()` method to `Word`.

## 0.15.1 (2025-06-18)

- Implemented `DerefMut`, `Index`, and `IndexMut` for `Word` (#434).

## 0.15.0 (2025-06-17)

- [BREAKING] Use a rich newtype for Merkle mountain range types' forest values (#400).
- Allow pre-sorted entries in `Smt` (#406).
- Added module and function documentation. (#408).
- Added default constructors to `MmrPeaks` and `PartialMmr` (#409).
- Added module and function documentation-2 (#410).
- [BREAKING] Replaced `RpoDigest` with `Word` struct (#411).
- Replaced deprecated #[clap(...)] with #[command(...)] and #[arg(...)] (#413).
- [BREAKING] Renamed `MerklePath::inner_nodes()` to `authenticated_nodes()` to better reflect its functionality (#415).
- Added `compute_root()`, `verify()`, and `authenticated_nodes()` to `SparseMerklePath` for parity with `MerklePath` (#415).
- [BREAKING] Replaced `RpxDigest` with `Word` struct (#420).
- Added `word!` macro to `miden-crypto` (#423).
- Added test vectors for RpoFalcon512 (#425).
- [BREAKING] Updated Winterfell dependency to v0.13 and licensed the project under the Apache 2.0 license (in addition to the MIT)(#433).
- [BREAKING] Incremented MSRV to 1.87.

## 0.14.1 (2025-05-31)

- Add module and function documentation. (#408).
- Added missing `PartialSmt` APIs (#417).

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
- Added range checks to `ntru_gen` for Falcon DSA (#391).
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
