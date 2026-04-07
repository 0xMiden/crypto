#!/bin/bash

set -euo pipefail

# Script to check curated feature combinations compile without warnings.
# The legacy workspace crates use cargo-hack across their public features,
# while the imported p3-miden crates keep their own targeted combinations.

echo "Checking miden workspace feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"

cargo hack check \
    -p miden-crypto \
    -p miden-crypto-derive \
    -p miden-field \
    -p miden-serde-utils \
    --each-feature \
    --exclude-features default \
    --all-targets

echo ""
echo "Checking imported p3-miden feature combinations..."

cargo check -p p3-miden-lifted-air --all-targets --no-default-features
cargo check -p p3-miden-stateful-hasher --all-targets --no-default-features
cargo check -p p3-miden-transcript --all-targets --no-default-features
cargo check -p p3-miden-lifted-stark --all-targets --no-default-features
cargo check -p p3-miden-lifted-stark --all-targets --features parallel
cargo check -p p3-miden-lifted-stark --all-targets --features testing
cargo check -p p3-miden-lifted-stark --all-targets --features testing,parallel

echo ""
echo "All curated feature combinations compiled successfully!"
