// Copyright (c) 2024 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copied from Plonky3 `p3-blake3-air` and kept in sync for permutation constants.

pub const BITS_PER_LIMB: usize = 16;
pub const U32_LIMBS: usize = 32 / BITS_PER_LIMB;

pub(crate) const IV: [[u16; 2]; 8] = [
    [0xE667, 0x6A09],
    [0xAE85, 0xBB67],
    [0xF372, 0x3C6E],
    [0xF53A, 0xA54F],
    [0x527F, 0x510E],
    [0x688C, 0x9B05],
    [0xD9AB, 0x1F83],
    [0xCD19, 0x5BE0],
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub(crate) fn permute<T: Clone>(m: &mut [T; 16]) {
    *m = core::array::from_fn(|i| m[MSG_PERMUTATION[i]].clone());
}
