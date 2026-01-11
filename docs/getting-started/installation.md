# Installation

## Requirements

- Rust 1.90 or later
- Cargo (comes with Rust)

## Basic Installation

Add `miden-crypto` to your `Cargo.toml`:

```toml
[dependencies]
miden-crypto = "0.21"
```

## Feature Flags

Miden Crypto supports several feature flags to customize functionality:

### Default Features

By default, the following features are enabled:

- `concurrent`: Enables multi-threaded implementations for better performance on multi-core CPUs
- `std`: Enables standard library support

### Optional Features

```toml
[dependencies]
miden-crypto = { version = "0.21", features = ["rocksdb", "hashmaps"] }
```

Available features:

- **`concurrent`**: Multi-threaded SMT operations (enabled by default)
- **`std`**: Standard library support (enabled by default)
- **`hashmaps`**: Uses `hashbrown` hashmaps for better performance (keys ordering in iterators not guaranteed)
- **`rocksdb`**: Enables RocksDB-backed storage for `LargeSmt` (implies `concurrent`)
- **`serde`**: Enables serialization support via Serde

### No Standard Library

For `no_std` environments (e.g., WebAssembly):

```toml
[dependencies]
miden-crypto = { version = "0.21", default-features = false }
```

Note: In `no_std` contexts, you must provide your own random number generator for key generation and signing operations.

## Building with Hardware Acceleration

### AVX2 Acceleration

For x86_64 platforms with AVX2 support:

```bash
RUSTFLAGS="-C target-feature=+avx2" cargo build --release
```

### AVX-512 Acceleration

For x86_64 platforms with AVX-512 support:

```bash
RUSTFLAGS="-C target-feature=+avx512f,+avx512dq" cargo build --release
```

### SVE Acceleration

For ARM64 platforms with SVE support:

```bash
RUSTFLAGS="-C target-feature=+sve" cargo build --release
```

### Native CPU Features

To automatically enable all features supported by your CPU:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Or add to `~/.cargo/config.toml`:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

**Note**: Using `target-cpu=native` creates binaries that are optimized for your build machine but may not run on other CPUs.

## Building with RocksDB

If you want to use the `rocksdb` feature, you'll need:

- `clang` accessible to the Rust toolchain
- `libclang` in your library path

On Linux, install via your package manager. On macOS, either Homebrew's `llvm` or Xcode's clang will work.

If clang is not in the default search paths, set environment variables:

```bash
export LDFLAGS="-L$LLVM_INSTALL_PATH/lib"
export CPPFLAGS="-I$LLVM_INSTALL_PATH/include"
```

## Verification

Verify your installation:

```bash
cargo build
cargo test
```

## Next Steps

- [Basic Usage](basic-usage.md): Learn how to use the library

