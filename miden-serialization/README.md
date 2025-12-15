# miden-serialization

Serialization and deserialization traits for Miden crypto primitives.

## Overview

This crate provides `Serializable` and `Deserializable` traits built on top of the
`embedded-io` ecosystem, supporting both `no_std` and `std` environments.

## Features

- `std`: Enable standard library support (includes `alloc`)
- `alloc`: Enable allocator support for `Vec`, `BTreeMap`, etc.
- `winterfell-compat`: Enable compatibility bridge with `winter-utils` traits

## Design

Built on `embedded-io::blocking::{Read, Write}` with extension traits `ByteRead` and
`ByteWrite` that add higher-level operations like reading/writing integers in
little-endian format and variable-length usize encoding (vint64).
