# Benchmarks

## Hash Functions

In the Miden VM, we make use of different hash functions. Some of these are "traditional" hash functions, like `BLAKE3`, which are optimized for out-of-STARK performance, while others are algebraic hash functions, like `Rescue Prime`, and are more optimized for a better performance inside the STARK. In what follows, we benchmark several such hash functions and compare against other constructions that are used by other proving systems. More precisely, we benchmark:

* **BLAKE3** as specified [here](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) and implemented [here](https://github.com/BLAKE3-team/BLAKE3) (with a wrapper exposed via this crate).
* **SHA3** as specified [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/sha/mod.rs).
* **Keccak256** as specified [here](https://keccak.team/specifications.html) and implemented [here](https://github.com/RustCrypto/hashes/tree/master/sha3) (with a wrapper exposed via this crate).
* **Rescue Prime Optimized (RPO)** as specified [here](https://eprint.iacr.org/2022/1577) and implemented in this crate.
* **Rescue Prime Extended (RPX)** a variant of the [xHash](https://eprint.iacr.org/2023/1045) hash function as implemented in this crate.
* **Poseidon2** as specified [here](https://eprint.iacr.org/2023/323) and implemented in this crate.

We benchmark the above hash functions using two scenarios. The first is a 2-to-1 $(a,b)\mapsto h(a,b)$ hashing where both $a$, $b$ and $h(a,b)$ are the digests corresponding to each of the hash functions. The second scenario is that of sequential hashing where we take a sequence of length $100$ field elements and hash these to produce a single digest. The digests are $4$ field elements in a prime field with modulus $2^{64} - 2^{32} + 1$ (i.e., 32 bytes) for Poseidon2, RPO, and RPX, and an array `[u8; 32]` for SHA3, BLAKE3, and Keccak256.

### Scenario 1: 2-to-1 hashing `h(a,b)`

| Function            | BLAKE3 | SHA3   | Keccak256 | Poseidon2 | RPO_256 | RPX_256 |
| ------------------- | :----: | :----: | :-------: | :-------: | :-----: | :-----: |
| Apple M1 Pro        | 76 ns  | 245 ns |           |           | 5.2 µs  | 2.7 µs  |
| Apple M2 Max        | 71 ns  | 233 ns |           |           | 4.6 µs  | 2.4 µs  |
| Apple M4 Max        | 48 ns  |        | 155 ns    | 0.7 µs    | 2.9 µs  | 1.5 µs  |
| Amazon Graviton 3   | 108 ns |        |           |           | 5.3 µs  | 3.1 µs  |
| Amazon Graviton 4   | 96 ns  |        |           |           | 5.1 µs  | 2.8 µs  |
| AMD Ryzen 9 5950X   | 64 ns  | 273 ns |           |           | 5.5 µs  |         |
| AMD EPYC 9R14       | 83 ns  |        |           |           | 4.3 µs  | 2.4 µs  |
| Intel Core i5-8279U | 68 ns  | 536 ns | 514 ns    | 1.7 µs    | 8.5 µs  | 4.4 µs  |
| Intel Xeon 8375C    | 67 ns  |        |           |           | 8.2 µs  |         |

### Scenario 2: Sequential hashing of 100 elements `h([a_0,...,a_99])`

| Function            | BLAKE3 | SHA3   | Keccak256 | Poseidon2 | RPO_256 | RPX_256 |
| ------------------- | :----: | :----: | :-------: | :-------: | :-----: | :-----: |
| Apple M1 Pro        | 1.0 µs | 1.5 µs |           |           | 69 µs   | 35 µs   |
| Apple M2 Max        | 0.9 µs | 1.5 µs |           |           | 60 µs   | 31 µs   |
| Apple M4 Max        | 0.7 µs |        | 0.9 µs    | 9.7 µs    | 37.5 µs | 19.4 µs |
| Amazon Graviton 3   | 1.4 µs |        |           |           | 69 µs   | 41 µs   |
| Amazon Graviton 4   | 1.2 µs |        |           |           | 67 µs   | 36 µs   |
| AMD Ryzen 9 5950X   | 0.8 µs | 1.7 µs |           |           | 72 µs   |         |
| AMD EPYC 9R14       | 0.9 µs |        |           |           | 56 µs   | 32 µs   |
| Intel Core i5-8279U | 0.9 µs |        | 3.4 µs    | 27 µs     | 107 µs  | 56 µs   |
| Intel Xeon 8375C    | 0.8 µs |        |           |           | 110 µs  |         |

Notes:
- On Graviton 3 and 4, RPO256 and RPX256 are run with SVE acceleration enabled.
- On AMD EPYC 9R14, RPO256 and RPX256 are run with AVX2 acceleration enabled.

## Sparse Merkle Tree

We build cryptographic data structures incorporating these hash functions. What follows are benchmarks of operations on sparse Merkle trees (SMTs) which use the above `RPO_256` hash function. We perform a batched modification of 1,000 values in a tree with 1,000,000 leaves (with the `hashmaps` feature to use the `hashbrown` crate).

### Scenario 1: SMT Construction (1M pairs)

| Hardware          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 7950X | 196 sec    | 15 sec     | 13x         |
| Apple M1 Air      | 352 sec    | 57 sec     | 6.2x        |
| Apple M1 Pro      | 351 sec    | 37 sec     | 9.5x        |
| Apple M4 Max      | 195 sec    | 15 sec     | 13x         |

### Scenario 2: SMT Batched Insertion (1k pairs, 1M leaves)

| Function          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 7950X | 201 ms     | 19 ms      | 11x         |
| Apple M1 Air      | 729 ms     | 406 ms     | 1.8x        |
| Apple M1 Pro      | 623 ms     | 86 ms      | 7.2x        |
| Apple M4 Max      | 212 ms     | 28 ms      | 7.6x        |

### Scenario 3: SMT Batched Update (1k pairs, 1M leaves)

| Function          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 7950X | 202 ms     | 19 ms      | 11x         |
| Apple M1 Air      | 691 ms     | 307 ms     | 2.3x        |
| Apple M1 Pro      | 419 ms     | 56 ms      | 7.5x        |
| Apple M4 Max      | 218 ms     | 24 ms      | 9.1x        |

Notes:
- On AMD Ryzen 9 7950X, benchmarks are run with AVX2 acceleration enabled.

## Instructions
Before you can run the benchmarks, you'll need to make sure you have Rust [installed](https://www.rust-lang.org/tools/install). After that, to run the benchmarks for RPO, Poseidon2, BLAKE3 and Keccak256, clone the current repository, and from the root directory of the repo run the following:

 ```
 cargo bench hash
 ```

To run the benchmarks for SHA3, clone the following [repository](https://github.com/Dominik1999/winterfell.git) as above, then checkout the `hash-functions-benches` branch, and from the root directory of the repo run the following:

```
cargo bench hash
```

To run the benchmarks for SMT operations, run the binary target with the `executable` feature:

```
cargo run --features=executable
```

The `concurrent` feature enables the concurrent benchmark, and is enabled by default. To run a sequential benchmark, disable the crate's default features:

```
cargo run --no-default-features --features=executable,hashmaps
```

The benchmark parameters may also be customized with the `-s`/`--size`, `-i`/`--insertions`, and `-u`/`--updates` options.
