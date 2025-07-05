# Miden Crypto

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/crypto/blob/main/LICENSE)
[![test](https://github.com/0xMiden/crypto/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/crypto/actions/workflows/test.yml)
[![build](https://github.com/0xMiden/crypto/actions/workflows/build.yml/badge.svg)](https://github.com/0xMiden/crypto/actions/workflows/build.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.85+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![CRATE](https://img.shields.io/crates/v/miden-crypto)](https://crates.io/crates/miden-crypto)

This crate contains cryptographic primitives used in Miden.

## Hash

[Hash module](./miden-crypto/src/hash) provides a set of cryptographic hash functions which are used by the Miden protocol. Currently, these functions are:

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function with 256-bit, 192-bit, or 160-bit output. The 192-bit and 160-bit outputs are obtained by truncating the 256-bit output of the standard BLAKE3.
- [RPO](https://eprint.iacr.org/2022/1577) hash function with 256-bit output. This hash function is an algebraic hash function suitable for recursive STARKs.
- [RPX](https://eprint.iacr.org/2023/1045) hash function with 256-bit output. Similar to RPO, this hash function is suitable for recursive STARKs but it is about 2x faster as compared to RPO.

For performance benchmarks of these hash functions and their comparison to other popular hash functions please see [here](./miden-crypto/benches/).

## Merkle

[Merkle module](./miden-crypto/src/merkle/) provides a set of data structures related to Merkle trees. All these data structures are implemented using the RPO hash function described above. The data structures are:

- `MerkleStore`: a collection of Merkle trees of different heights designed to efficiently store trees with common subtrees. When instantiated with `RecordingMap`, a Merkle store records all accesses to the original data.
- `MerkleTree`: a regular fully-balanced binary Merkle tree. The depth of this tree can be at most 64.
- `Mmr`: a Merkle mountain range structure designed to function as an append-only log.
- `PartialMerkleTree`: a partial view of a Merkle tree where some sub-trees may not be known. This is similar to a collection of Merkle paths all resolving to the same root. The length of the paths can be at most 64.
- `PartialMmr`: a partial view of a Merkle mountain range structure.
- `SimpleSmt`: a Sparse Merkle Tree (with no compaction), mapping 64-bit keys to 4-element values.
- `Smt`: a Sparse Merkle tree (with compaction at depth 64), mapping 4-element keys to 4-element values.

The module also contains additional supporting components such as `NodeIndex`, `MerklePath`, and `MerkleError` to assist with tree indexation, opening proofs, and reporting inconsistent arguments/state.

## Signatures

[DSA module](./miden-crypto/src/dsa) provides a set of digital signature schemes supported by default in the Miden VM. Currently, these schemes are:

- `RPO Falcon512`: a variant of the [Falcon](https://falcon-sign.info/) signature scheme. This variant differs from the standard in that instead of using SHAKE256 hash function in the _hash-to-point_ algorithm we use RPO256. This makes the signature more efficient to verify in Miden VM.

For the above signatures, key generation, signing, and signature verification are available for both `std` and `no_std` contexts (see [crate features](#crate-features) below). However, in `no_std` context, the user is responsible for supplying the key generation and signing procedures with a random number generator.

## Pseudo-Random Element Generator

[Pseudo random element generator module](./miden-crypto/src/rand/) provides a set of traits and data structures that facilitate generating pseudo-random elements in the context of Miden protocol. The module currently includes:

- `FeltRng`: a trait for generating random field elements and random 4 field elements.
- `RpoRandomCoin`: a struct implementing `FeltRng` as well as the [`RandomCoin`](https://github.com/facebook/winterfell/blob/main/crypto/src/random/mod.rs) trait using RPO hash function.
- `RpxRandomCoin`: a struct implementing `FeltRng` as well as the [`RandomCoin`](https://github.com/facebook/winterfell/blob/main/crypto/src/random/mod.rs) trait using RPX hash function.

## Make commands

We use `make` to automate building, testing, and other processes. In most cases, `make` commands are wrappers around `cargo` commands with specific arguments. You can view the list of available commands in the [Makefile](Makefile), or run the following command:

```shell
make
```

## Crate features

This crate can be compiled with the following features:

- `concurrent`- enabled by default; enables multi-threaded implementation of `Smt::with_entries()` which significantly improves performance on multi-core CPUs.
- `std` - enabled by default and relies on the Rust standard library.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
- `smt_hashmaps` - uses hashbrown hashmaps in SMT implementation which significantly improves performance of SMT updating. Keys ordering in SMT iterators is not guaranteed when this feature is enabled.

All of these features imply the use of [alloc](https://doc.rust-lang.org/alloc/) to support heap-allocated collections.

To compile with `no_std`, disable default features via `--no-default-features` flag or using the following command:

```shell
make build-no-std
```

### AVX2 acceleration

On platforms with [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions) support, RPO and RPX hash function can be accelerated by using the vector processing unit. To enable AVX2 acceleration, the code needs to be compiled with the `avx2` target feature enabled. For example:

```shell
make build-avx2
```

### SVE acceleration

On platforms with [SVE](<https://en.wikipedia.org/wiki/AArch64#Scalable_Vector_Extension_(SVE)>) support, RPO and RPX hash function can be accelerated by using the vector processing unit. To enable SVE acceleration, the code needs to be compiled with the `sve` target feature enabled. For example:

```shell
make build-sve
```

## Testing

The best way to test the library is using our [Makefile](Makefile), this will enable you to use our pre-defined optimized testing commands:

```shell
make test
```

For example, some of the functions are heavy and might take a while for the tests to complete if using simply `cargo test`. In order to test in release and optimized mode, we have to replicate the test conditions of the development mode so all debug assertions can be verified.

We do that by enabling some special [flags](https://doc.rust-lang.org/cargo/reference/profiles.html) for the compilation (which we have set as a default in our [Makefile](Makefile)):

```shell
RUSTFLAGS="-C debug-assertions -C overflow-checks -C debuginfo=2" cargo test --release
```

## Fuzzing

The `fuzz-smt` fuzz target is designed to test the `Smt` implementation. It generates random SMT entries and updates, and then compares the results of the sequential and parallel implementations.

Before running the fuzz tests, ensure you have `cargo-fuzz` installed:

```shell
cargo install cargo-fuzz
```

To run the fuzz target, use:

```shell
make fuzz-smt
```

## License

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE) licenses, without any additional terms or conditions.
