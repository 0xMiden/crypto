#!/usr/bin/env bash

set -euo pipefail

cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features parallel
cargo check -p p3-miden-lifted-stark --all-targets --no-default-features
cargo check -p p3-miden-lifted-stark --all-targets --features parallel
cargo check -p p3-miden-lifted-stark --all-targets --features testing
cargo check -p p3-miden-lifted-stark --all-targets --features testing,parallel
