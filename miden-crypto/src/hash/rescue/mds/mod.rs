use std::println;

use super::{Felt, STATE_WIDTH, ZERO};

mod freq;
pub use freq::mds_multiply_freq;

const TWO_POWER_32: Felt = Felt::new(1 << 32);

// MDS MULTIPLICATION
// ================================================================================================

#[inline(always)]
pub fn apply_mds(state: &mut [Felt; STATE_WIDTH]) {
    let mut result = [ZERO; STATE_WIDTH];

    // Using the linearity of the operations we can split the state into a low||high decomposition
    // and operate on each with no overflow and then combine/reduce the result to a field element.
    // The no overflow is guaranteed by the fact that the MDS matrix is a small powers of two in
    // frequency domain.
    let mut state_l = [0u64; STATE_WIDTH];
    let mut state_h = [0u64; STATE_WIDTH];

    for r in 0..STATE_WIDTH {
        let s = state[r].inner();
        state_h[r] = s >> 32;
        state_l[r] = (s as u32) as u64;
    }

    let state_h = mds_multiply_freq(state_h);
    let state_l = mds_multiply_freq(state_l);

    for r in 0..STATE_WIDTH {
               //    result[r] = Felt::from_mont(state_h[r]) * TWO_POWER_32 + Felt::from_mont(state_l[r]);
        //result[r] =    Felt::from_mont(mont_mul_by_2pow32_u40(state_h[r])) + Felt::from_mont(state_l[r]);

        // Idea: inner lhs above plus inner rhs can be added as u64 and then reduced modulo p
        //
        // let (res, over) = lhs.overflow_add(rhs);
        // res.wrapping_add(0u32.wrapping_sub(over as u32) as u64)

        //let lhs = mont_mul_by_2pow32_u40(state_h[r]);
        //let rhs = state_l[r];
        //let (res, over) = lhs.overflowing_add(rhs);
        //let u = res.wrapping_add(0u32.wrapping_sub(over as u32) as u64);
        //result[r] =    Felt::from_mont(u);

        let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
        let s_hi = (s >> 64) as u64;
        let s_lo = s as u64;
        let z = (s_hi << 32) - s_hi;
        let (res, over) = s_lo.overflowing_add(z);

        result[r] = Felt::from_mont(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64));
    }
    *state = result;
}

#[inline(always)]
pub fn mont_mul_by_2pow32_u40(x: u64) -> u64 {
    debug_assert!(x < (1u64 << 40));

    let h = x >> 32;
    let l = x & 0xFFFF_FFFF;
    let t = l + h;

    let r = t.wrapping_shl(32).wrapping_sub(h);

    r
}

#[test]
fn test(){
    let x:u64 = (1 << 40) -78000 ;
    let x =5641;

    let x_mont = Felt::from_mont(x);

    let x_mont_shifted_0 = x_mont * Felt::new(1 << 32);

    let x_mont_shifted_1 = Felt::from_mont(mont_mul_by_2pow32_u40(x));

    println!("0 is {:?}", x_mont_shifted_0);
    println!("1 is {:?}", x_mont_shifted_1);

}

// MDS MATRIX
// ================================================================================================

/// RPO MDS matrix
pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = [
    [
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
    ],
    [
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
    ],
    [
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
    ],
    [
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
    ],
    [
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
    ],
    [
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
    ],
    [
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
    ],
    [
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
    ],
    [
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
    ],
    [
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
    ],
];
