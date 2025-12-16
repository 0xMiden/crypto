# Miden Serialization Utilities

This crate provides serialization and deserialization utilities for Miden projects.

## Features

- `ByteReader` trait for reading primitive values from byte sources
- `ByteWriter` trait for writing primitive values to byte sinks
- `Serializable` and `Deserializable` traits for custom types
- Support for both `std` and `no_std` environments

## Crate Features

- `std` - enabled by default; enables standard library support
- `winter-compat` - provides `Serializable` and `Deserializable` implementations for types from the `winter-math` and `winter-utils` crates (specifically for `Felt` field elements). This feature exists to work around Rust's orphan rule, which prevents implementing external traits on external types. By implementing these traits in this intermediate crate, both Miden and Winter ecosystem crates can use a common serialization interface

## License

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](../LICENSE-MIT) and [Apache 2.0](../LICENSE-APACHE) licenses, without any additional terms or conditions.
