use p3_field::{PrimeCharacteristicRing, PrimeField64};

use super::{Felt, STATE_WIDTH, ZERO};
mod freq;
pub use freq::mds_multiply_freq;
use lazy_static::lazy_static;

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
        let s = state[r].as_canonical_u64();
        state_h[r] = s >> 32;
        state_l[r] = (s as u32) as u64;
    }

    let state_h = mds_multiply_freq(state_h);
    let state_l = mds_multiply_freq(state_l);

    for r in 0..STATE_WIDTH {
        let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
        let s_hi = (s >> 64) as u64;
        let s_lo = s as u64;
        let z = (s_hi << 32) - s_hi;
        let (res, over) = s_lo.overflowing_add(z);

        result[r] = Felt::from_u64(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64));
    }
    *state = result;
}

// MDS MATRIX
// ================================================================================================
lazy_static! {
/// RPO MDS matrix
    static ref MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = [
    [
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
    ],
    [
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
    ],
    [
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
    ],
    [
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
    ],
    [
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
    ],
    [
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
    ],
    [
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
    ],
    [
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
    ],
    [
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
    ],
    [
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
        Felt::from_u64(8),
    ],
    [
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
        Felt::from_u64(23),
    ],
    [
        Felt::from_u64(23),
        Felt::from_u64(8),
        Felt::from_u64(26),
        Felt::from_u64(13),
        Felt::from_u64(10),
        Felt::from_u64(9),
        Felt::from_u64(7),
        Felt::from_u64(6),
        Felt::from_u64(22),
        Felt::from_u64(21),
        Felt::from_u64(8),
        Felt::from_u64(7),
    ],
    ];
}
