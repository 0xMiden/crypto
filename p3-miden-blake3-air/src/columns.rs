// Copyright (c) 2024 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Derived from Plonky3 `p3-blake3-air` `columns.rs`: same permutation witness layout,
// but only the first six 32-bit output words are materialized (192 bits).

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::constants::U32_LIMBS;

/// Columns for one Blake3 **compression** (same as upstream), but output trace holds only
/// **192 bits** of the xor-layer output: all of `state[0] ⊕ state[2]` (4 words) and the first
/// two words of `state[1] ⊕ state[3]`.
///
/// The remaining xor combinations are implied by the fully constrained round state and are not
/// stored as separate columns.
#[repr(C)]
pub struct Blake3_192Cols<T> {
    pub inputs: [[T; 32]; 16],
    pub chaining_values: [[[T; 32]; 4]; 2],
    pub counter_low: [T; 32],
    pub counter_hi: [T; 32],
    pub block_len: [T; 32],
    pub flags: [T; 32],
    pub initial_row0: [[T; U32_LIMBS]; 4],
    pub initial_row2: [[T; U32_LIMBS]; 4],
    pub full_rounds: [FullRound<T>; 7],
    pub final_round_helpers: [[T; 32]; 4],
    /// `state[0][i] ⊕ state[2][i]` for `i ∈ 0..4`.
    pub outputs0: [[T; 32]; 4],
    /// `state[1][i] ⊕ state[3][i]` for `i ∈ 0..2` only.
    pub outputs1_head: [[T; 32]; 2],
}

#[repr(C)]
pub struct Blake3State<T> {
    pub row0: [[T; U32_LIMBS]; 4],
    pub row1: [[T; 32]; 4],
    pub row2: [[T; U32_LIMBS]; 4],
    pub row3: [[T; 32]; 4],
}

#[repr(C)]
pub struct FullRound<T> {
    pub state_prime: Blake3State<T>,
    pub state_middle: Blake3State<T>,
    pub state_middle_prime: Blake3State<T>,
    pub state_output: Blake3State<T>,
}

#[repr(C)]
pub(crate) struct QuarterRound<'a, T, U> {
    pub a: &'a [T; U32_LIMBS],
    pub b: &'a [T; 32],
    pub c: &'a [T; U32_LIMBS],
    pub d: &'a [T; 32],
    pub m_two_i: &'a [U; U32_LIMBS],
    pub a_prime: &'a [T; U32_LIMBS],
    pub b_prime: &'a [T; 32],
    pub c_prime: &'a [T; U32_LIMBS],
    pub d_prime: &'a [T; 32],
    pub m_two_i_plus_one: &'a [U; U32_LIMBS],
    pub a_output: &'a [T; U32_LIMBS],
    pub b_output: &'a [T; 32],
    pub c_output: &'a [T; U32_LIMBS],
    pub d_output: &'a [T; 32],
}

pub const NUM_BLAKE3_192_COLS: usize = size_of::<Blake3_192Cols<u8>>();

impl<T> Borrow<Blake3_192Cols<T>> for [T] {
    fn borrow(&self) -> &Blake3_192Cols<T> {
        debug_assert_eq!(self.len(), NUM_BLAKE3_192_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Blake3_192Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Blake3_192Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Blake3_192Cols<T> {
        debug_assert_eq!(self.len(), NUM_BLAKE3_192_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Blake3_192Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
