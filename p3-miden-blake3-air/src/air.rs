// Copyright (c) 2024 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Derived from Plonky3 `p3-blake3-air` `air.rs`: same compression constraints, but only six
// 32-bit xor outputs are wired (192 bits).

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use itertools::izip;
use p3_air::{
    Air, AirBuilder, BaseAir, WindowAccess,
    utils::{add2, add3, pack_bits_le, xor_32_shift},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, rngs::SmallRng};

use crate::{
    columns::{Blake3_192Cols, Blake3State, FullRound, NUM_BLAKE3_192_COLS, QuarterRound},
    constants::{BITS_PER_LIMB, IV, permute},
    generation::generate_trace_rows,
};

/// Assumes the field size is at least 16 bits.
#[derive(Debug)]
pub struct Blake3_192Air {}

impl Blake3_192Air {
    pub fn generate_trace_rows<F: PrimeField64>(
        &self,
        num_hashes: usize,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let mut rng = SmallRng::seed_from_u64(1);
        let inputs = (0..num_hashes).map(|_| rng.random()).collect::<Vec<_>>();
        generate_trace_rows(inputs, extra_capacity_bits)
    }

    fn quarter_round_function<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        trace: &QuarterRound<'_, <AB as AirBuilder>::Var, <AB as AirBuilder>::Expr>,
    ) {
        let b_0_16 = pack_bits_le(trace.b[..BITS_PER_LIMB].iter().copied());
        let b_16_32 = pack_bits_le(trace.b[BITS_PER_LIMB..].iter().copied());

        add3(
            builder,
            trace.a_prime,
            trace.a,
            &[b_0_16, b_16_32],
            trace.m_two_i,
        );

        xor_32_shift(builder, trace.a_prime, trace.d, trace.d_prime, 16);

        let d_prime_0_16 = pack_bits_le(trace.d_prime[..BITS_PER_LIMB].iter().copied());
        let d_prime_16_32 = pack_bits_le(trace.d_prime[BITS_PER_LIMB..].iter().copied());
        add2(
            builder,
            trace.c_prime,
            trace.c,
            &[d_prime_0_16, d_prime_16_32],
        );

        xor_32_shift(builder, trace.c_prime, trace.b, trace.b_prime, 12);

        let b_prime_0_16 = pack_bits_le(trace.b_prime[..BITS_PER_LIMB].iter().copied());
        let b_prime_16_32 = pack_bits_le(trace.b_prime[BITS_PER_LIMB..].iter().copied());

        add3(
            builder,
            trace.a_output,
            trace.a_prime,
            &[b_prime_0_16, b_prime_16_32],
            trace.m_two_i_plus_one,
        );

        xor_32_shift(builder, trace.a_output, trace.d_prime, trace.d_output, 8);

        let d_output_0_16 = pack_bits_le(trace.d_output[..BITS_PER_LIMB].iter().copied());
        let d_output_16_32 = pack_bits_le(trace.d_output[BITS_PER_LIMB..].iter().copied());
        add2(
            builder,
            trace.c_output,
            trace.c_prime,
            &[d_output_0_16, d_output_16_32],
        );

        xor_32_shift(builder, trace.c_output, trace.b_prime, trace.b_output, 7);
    }

    const fn full_round_to_column_quarter_round<'a, T: Copy, U>(
        &self,
        input: &'a Blake3State<T>,
        round_data: &'a FullRound<T>,
        m_vector: &'a [[U; 2]; 16],
        index: usize,
    ) -> QuarterRound<'a, T, U> {
        QuarterRound {
            a: &input.row0[index],
            b: &input.row1[index],
            c: &input.row2[index],
            d: &input.row3[index],

            m_two_i: &m_vector[2 * index],

            a_prime: &round_data.state_prime.row0[index],
            b_prime: &round_data.state_prime.row1[index],
            c_prime: &round_data.state_prime.row2[index],
            d_prime: &round_data.state_prime.row3[index],

            m_two_i_plus_one: &m_vector[2 * index + 1],

            a_output: &round_data.state_middle.row0[index],
            b_output: &round_data.state_middle.row1[index],
            c_output: &round_data.state_middle.row2[index],
            d_output: &round_data.state_middle.row3[index],
        }
    }

    const fn full_round_to_diagonal_quarter_round<'a, T: Copy, U>(
        &self,
        round_data: &'a FullRound<T>,
        m_vector: &'a [[U; 2]; 16],
        index: usize,
    ) -> QuarterRound<'a, T, U> {
        QuarterRound {
            a: &round_data.state_middle.row0[index],
            b: &round_data.state_middle.row1[(index + 1) % 4],
            c: &round_data.state_middle.row2[(index + 2) % 4],
            d: &round_data.state_middle.row3[(index + 3) % 4],

            m_two_i: &m_vector[2 * index + 8],

            a_prime: &round_data.state_middle_prime.row0[index],
            b_prime: &round_data.state_middle_prime.row1[(index + 1) % 4],
            c_prime: &round_data.state_middle_prime.row2[(index + 2) % 4],
            d_prime: &round_data.state_middle_prime.row3[(index + 3) % 4],

            m_two_i_plus_one: &m_vector[2 * index + 9],

            a_output: &round_data.state_output.row0[index],
            b_output: &round_data.state_output.row1[(index + 1) % 4],
            c_output: &round_data.state_output.row2[(index + 2) % 4],
            d_output: &round_data.state_output.row3[(index + 3) % 4],
        }
    }

    fn verify_round<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        input: &Blake3State<AB::Var>,
        round_data: &FullRound<AB::Var>,
        m_vector: &[[AB::Expr; 2]; 16],
    ) {
        let trace_column_0 =
            self.full_round_to_column_quarter_round(input, round_data, m_vector, 0);
        self.quarter_round_function(builder, &trace_column_0);

        let trace_column_1 =
            self.full_round_to_column_quarter_round(input, round_data, m_vector, 1);
        self.quarter_round_function(builder, &trace_column_1);

        let trace_column_2 =
            self.full_round_to_column_quarter_round(input, round_data, m_vector, 2);
        self.quarter_round_function(builder, &trace_column_2);

        let trace_column_3 =
            self.full_round_to_column_quarter_round(input, round_data, m_vector, 3);
        self.quarter_round_function(builder, &trace_column_3);

        let trace_diagonal_0 = self.full_round_to_diagonal_quarter_round(round_data, m_vector, 0);
        self.quarter_round_function(builder, &trace_diagonal_0);

        let trace_diagonal_1 = self.full_round_to_diagonal_quarter_round(round_data, m_vector, 1);
        self.quarter_round_function(builder, &trace_diagonal_1);

        let trace_diagonal_2 = self.full_round_to_diagonal_quarter_round(round_data, m_vector, 2);
        self.quarter_round_function(builder, &trace_diagonal_2);

        let trace_diagonal_3 = self.full_round_to_diagonal_quarter_round(round_data, m_vector, 3);
        self.quarter_round_function(builder, &trace_diagonal_3);
    }
}

impl<F> BaseAir<F> for Blake3_192Air {
    fn width(&self) -> usize {
        NUM_BLAKE3_192_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder> Air<AB> for Blake3_192Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake3_192Cols<AB::Var> = main.current_slice().borrow();

        let initial_row_3 = [
            local.counter_low,
            local.counter_hi,
            local.block_len,
            local.flags,
        ];

        local
            .inputs
            .iter()
            .chain(local.chaining_values[0].iter())
            .chain(local.chaining_values[1].iter())
            .chain(initial_row_3.iter())
            .for_each(|elem| {
                elem.iter().for_each(|&bool| builder.assert_bool(bool));
            });

        local.chaining_values[0]
            .iter()
            .zip(local.initial_row0)
            .for_each(|(bits, word)| {
                let low_16 = pack_bits_le(bits[..BITS_PER_LIMB].iter().copied());
                let hi_16 = pack_bits_le(bits[BITS_PER_LIMB..].iter().copied());
                builder.assert_eq(low_16, word[0]);
                builder.assert_eq(hi_16, word[1]);
            });

        local
            .initial_row2
            .iter()
            .zip(IV)
            .for_each(|(row_elem, constant)| {
                builder.assert_eq(row_elem[0], AB::Expr::from_u16(constant[0]));
                builder.assert_eq(row_elem[1], AB::Expr::from_u16(constant[1]));
            });

        let mut m_values: [[AB::Expr; 2]; 16] = local.inputs.map(|bits| {
            [
                pack_bits_le(bits[..BITS_PER_LIMB].iter().copied()),
                pack_bits_le(bits[BITS_PER_LIMB..].iter().copied()),
            ]
        });

        let initial_state = Blake3State {
            row0: local.initial_row0,
            row1: local.chaining_values[1],
            row2: local.initial_row2,
            row3: initial_row_3,
        };

        self.verify_round(builder, &initial_state, &local.full_rounds[0], &m_values);
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[0].state_output,
            &local.full_rounds[1],
            &m_values,
        );
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[1].state_output,
            &local.full_rounds[2],
            &m_values,
        );
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[2].state_output,
            &local.full_rounds[3],
            &m_values,
        );
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[3].state_output,
            &local.full_rounds[4],
            &m_values,
        );
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[4].state_output,
            &local.full_rounds[5],
            &m_values,
        );
        permute(&mut m_values);

        self.verify_round(
            builder,
            &local.full_rounds[5].state_output,
            &local.full_rounds[6],
            &m_values,
        );

        local
            .final_round_helpers
            .iter()
            .zip(local.full_rounds[6].state_output.row2)
            .for_each(|(bits, word)| {
                let low_16 = pack_bits_le(bits[..BITS_PER_LIMB].iter().copied());
                let hi_16 = pack_bits_le(bits[BITS_PER_LIMB..].iter().copied());
                builder.assert_eq(low_16, word[0]);
                builder.assert_eq(hi_16, word[1]);
            });

        local
            .final_round_helpers
            .iter()
            .chain(local.outputs0.iter())
            .for_each(|bits| bits.iter().for_each(|&bit| builder.assert_bool(bit)));

        for (out_bits, left_words, right_bits) in izip!(
            local.outputs0,
            local.full_rounds[6].state_output.row0,
            local.final_round_helpers
        ) {
            xor_32_shift(builder, &left_words, &out_bits, &right_bits, 0);
        }

        for (out_bits, left_bits, right_bits) in izip!(
            local.outputs1_head,
            local.full_rounds[6].state_output.row1,
            local.full_rounds[6].state_output.row3
        ) {
            for (out_bit, left_bit, right_bit) in izip!(out_bits, left_bits, right_bits) {
                builder.assert_eq(out_bit, left_bit.into().xor(&right_bit.into()));
            }
        }
    }
}
