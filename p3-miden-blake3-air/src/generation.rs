// Copyright (c) 2024 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Derived from Plonky3 `p3-blake3-air` `generation.rs`.

use alloc::vec::Vec;
use core::array;

use p3_air::utils::u32_to_bits_le;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use tracing::instrument;

use crate::{
    columns::{Blake3_192Cols, Blake3State, FullRound, NUM_BLAKE3_192_COLS},
    constants::{IV, permute},
};

#[instrument(name = "generate Blake3-192 trace", skip_all)]
pub fn generate_trace_rows<F: PrimeField64>(
    inputs: Vec<[u32; 24]>,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<F> {
    generate_trace_rows_inner(inputs, extra_capacity_bits)
}

fn generate_trace_rows_inner<F: PrimeField64>(
    inputs: Vec<[u32; 24]>,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<F> {
    let num_rows = inputs.len();
    assert!(
        num_rows.is_power_of_two(),
        "Callers expected to pad inputs to VECTOR_LEN times a power of two"
    );

    let trace_length = num_rows * NUM_BLAKE3_192_COLS;

    let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
    long_trace.truncate(trace_length);

    let mut trace = RowMajorMatrix::new(long_trace, NUM_BLAKE3_192_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<Blake3_192Cols<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), num_rows);

    rows.par_iter_mut()
        .zip(inputs)
        .enumerate()
        .for_each(|(counter, (row, input))| {
            generate_trace_rows_for_perm(row, input, counter, num_rows);
        });

    trace
}

fn generate_trace_rows_for_perm<F: PrimeField64>(
    row: &mut Blake3_192Cols<F>,
    input: [u32; 24],
    counter: usize,
    block_len: usize,
) {
    row.inputs = array::from_fn(|i| u32_to_bits_le(input[i]));
    row.chaining_values =
        array::from_fn(|i| array::from_fn(|j| u32_to_bits_le(input[16 + 4 * i + j])));

    row.counter_low = u32_to_bits_le(counter as u32);
    row.counter_hi = u32_to_bits_le(counter.wrapping_shr(32) as u32);
    row.block_len = u32_to_bits_le(block_len as u32);

    row.initial_row0 = array::from_fn(|i| {
        [
            F::from_u16(input[16 + i] as u16),
            F::from_u16((input[16 + i] >> 16) as u16),
        ]
    });

    row.initial_row2 = array::from_fn(|i| [F::from_u16(IV[i][0]), F::from_u16(IV[i][1])]);

    let mut m_vec: [u32; 16] = array::from_fn(|i| input[i]);
    let mut state = [
        [input[16], input[16 + 1], input[16 + 2], input[16 + 3]],
        [input[16 + 4], input[16 + 5], input[16 + 6], input[16 + 7]],
        [
            (IV[0][0] as u32) + ((IV[0][1] as u32) << 16),
            (IV[1][0] as u32) + ((IV[1][1] as u32) << 16),
            (IV[2][0] as u32) + ((IV[2][1] as u32) << 16),
            (IV[3][0] as u32) + ((IV[3][1] as u32) << 16),
        ],
        [
            counter as u32,
            counter.wrapping_shr(32) as u32,
            block_len as u32,
            0,
        ],
    ];

    generate_trace_row_for_round(&mut row.full_rounds[0], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[1], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[2], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[3], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[4], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[5], &mut state, &m_vec);
    permute(&mut m_vec);
    generate_trace_row_for_round(&mut row.full_rounds[6], &mut state, &m_vec);

    row.final_round_helpers = array::from_fn(|i| u32_to_bits_le(state[2][i]));

    row.outputs0 = array::from_fn(|i| u32_to_bits_le(state[0][i] ^ state[2][i]));
    row.outputs1_head = array::from_fn(|i| u32_to_bits_le(state[1][i] ^ state[3][i]));
}

fn generate_trace_row_for_round<F: PrimeField64>(
    round_data: &mut FullRound<F>,
    state: &mut [[u32; 4]; 4],
    m_vec: &[u32; 16],
) {
    (0..4).for_each(|i| {
        (state[0][i], state[1][i], state[2][i], state[3][i]) = verifiable_half_round(
            state[0][i],
            state[1][i],
            state[2][i],
            state[3][i],
            m_vec[2 * i],
            false,
        );
    });

    save_state_to_trace(&mut round_data.state_prime, state);

    (0..4).for_each(|i| {
        (state[0][i], state[1][i], state[2][i], state[3][i]) = verifiable_half_round(
            state[0][i],
            state[1][i],
            state[2][i],
            state[3][i],
            m_vec[2 * i + 1],
            true,
        );
    });

    save_state_to_trace(&mut round_data.state_middle, state);

    (0..4).for_each(|i| {
        (
            state[0][i],
            state[1][(i + 1) % 4],
            state[2][(i + 2) % 4],
            state[3][(i + 3) % 4],
        ) = verifiable_half_round(
            state[0][i],
            state[1][(i + 1) % 4],
            state[2][(i + 2) % 4],
            state[3][(i + 3) % 4],
            m_vec[8 + 2 * i],
            false,
        );
    });

    save_state_to_trace(&mut round_data.state_middle_prime, state);

    (0..4).for_each(|i| {
        (
            state[0][i],
            state[1][(i + 1) % 4],
            state[2][(i + 2) % 4],
            state[3][(i + 3) % 4],
        ) = verifiable_half_round(
            state[0][i],
            state[1][(i + 1) % 4],
            state[2][(i + 2) % 4],
            state[3][(i + 3) % 4],
            m_vec[9 + 2 * i],
            true,
        );
    });

    save_state_to_trace(&mut round_data.state_output, state);
}

const fn verifiable_half_round(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    m: u32,
    flag: bool,
) -> (u32, u32, u32, u32) {
    let (rot_1, rot_2) = if flag { (8, 7) } else { (16, 12) };

    a = a.wrapping_add(b);
    a = a.wrapping_add(m);

    d = (d ^ a).rotate_right(rot_1);

    c = c.wrapping_add(d);

    b = (b ^ c).rotate_right(rot_2);

    (a, b, c, d)
}

fn save_state_to_trace<R: PrimeCharacteristicRing>(
    trace: &mut Blake3State<R>,
    state: &[[u32; 4]; 4],
) {
    trace.row0 = array::from_fn(|i| {
        [
            R::from_u16(state[0][i] as u16),
            R::from_u16((state[0][i] >> 16) as u16),
        ]
    });
    trace.row1 = array::from_fn(|i| u32_to_bits_le(state[1][i]));
    trace.row2 = array::from_fn(|i| {
        [
            R::from_u16(state[2][i] as u16),
            R::from_u16((state[2][i] >> 16) as u16),
        ]
    });
    trace.row3 = array::from_fn(|i| u32_to_bits_le(state[3][i]));
}
