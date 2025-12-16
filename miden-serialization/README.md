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

## Usage

### Basic Serialization (no_std)

```rust
use miden_serialization::{Serializable, Deserializable, SliceReader};

// Serialize to a byte vector
let value = 42u32;
let bytes = value.to_bytes();

// Deserialize from bytes
let decoded = u32::read_from_bytes(&bytes).unwrap();
assert_eq!(value, decoded);
```

### Custom Type Implementation

```rust
use miden_serialization::{Serializable, Deserializable, ByteRead, ByteWrite};

struct MyPoint {
    x: u32,
    y: u32,
}

impl Serializable for MyPoint {
    fn write_into<W: ByteWrite>(&self, target: &mut W) -> Result<(), W::Error> {
        self.x.write_into(target)?;
        self.y.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>() * 2
    }
}

impl Deserializable for MyPoint {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok(MyPoint {
            x: u32::read_from(source)?,
            y: u32::read_from(source)?,
        })
    }
}
```

### Working with Files (std feature)

```rust
use miden_serialization::{Serializable, Deserializable, StdReadAdapter};
use std::fs::File;

// Write to file
let value = vec![1u32, 2, 3, 4, 5];
let mut file = File::create("data.bin")?;
let mut writer = StdWriteAdapter::new(file);
value.write_into(&mut writer)?;

// Read from file
let file = File::open("data.bin")?;
let mut reader = StdReadAdapter::new(file);
let decoded = Vec::<u32>::read_from(&mut reader)?;
```

## Comparison with winter-utils

| Feature | winter-utils | miden-serialization |
|---------|-------------|---------------------|
| no_std support | ✅ | ✅ |
| Foundation | Custom traits | embedded-io |
| Error handling | Panics on write | Result-based |
| Ecosystem | Winterfell-specific | Rust embedded ecosystem |
| Lines of code | ~2000 | ~800 |

## Migration Guide

If you're migrating from `winter-utils`:

1. Replace `winter_utils::Serializable` with `miden_serialization::Serializable`
2. Replace `winter_utils::Deserializable` with `miden_serialization::Deserializable`
3. Update `write_into` to return `Result<(), W::Error>` instead of panicking
4. Replace `ByteWriter` with `ByteWrite` and `ByteReader` with `ByteRead`
5. For gradual migration, enable the `winterfell-compat` feature

## License

Licensed under MIT OR Apache-2.0
