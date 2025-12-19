#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"

# Run cargo-hack with comprehensive feature checking
# Note: We exclude 'default' to test non-default feature combinations
# and use --each-feature to test each feature individually
cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default \
    --all-targets

echo ""
echo "All feature combinations compiled successfully!"
