// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Compatibility layer for winter-utils traits.
//!
//! This module is intentionally minimal - it simply ensures winter-utils is available
//! as a transitive dependency when the winter-compat feature is enabled.
//!
//! Types that need to work with winter-crypto (which requires winter_utils traits)
//! should implement both miden-serde-utils traits AND winter_utils traits with
//! identical implementations.
