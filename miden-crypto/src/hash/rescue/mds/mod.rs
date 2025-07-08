use core::u64;
use super::{Felt, STATE_WIDTH, ZERO};

mod freq;
pub use freq::mds_multiply_freq;
use winter_math::StarkField;

//const TWO_POWER_32: Felt = Felt::new(1 << 32);

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
        // Solution 0: base solution
        // ================================================================================================

        //let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
        //let s_hi = (s >> 64) as u64;
        //let s_lo = s as u64;
        //let z = (s_hi << 32) - s_hi;
        //let (res, over) = s_lo.overflowing_add(z);
        //result[r] = Felt::new(
            //Felt::from_mont(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64)).as_int(),
        //);

        // Solution 1: Modular reduction
        // ================================================================================================

        let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
        let s_hi = (s >> 64) as u64;
        let s_lo = s as u64;
        let z = (s_hi << 32) - s_hi;
        let (res, over) = s_lo.overflowing_add(z);
        let tmp = res.wrapping_add(0u32.wrapping_sub(over as u32) as u64);

        // version 1: branching
        let res = if tmp > Felt::MODULUS { tmp - Felt::MODULUS } else { tmp };
        result[r] = Felt::from_mont(res);

        // version 2: constant-time
        //let (res, over) = tmp.overflowing_sub(Felt::MODULUS);
        //let mask = 0u64.wrapping_sub(over as u64);
        //let res = res.wrapping_add(Felt::MODULUS & mask);
        //result[r] = Felt::from_mont(res);

        // Solution 2: apply from_mont on the limbs before composing
        // ================================================================================================

        // Since we are decomposing an element in the range 0 to p-1 into two limbs each a u32, we can get
        // an upper bound on the size of the resulting state from the multiplication by the matrix. Indeed, given
        // the current MDS matrix, the size of each entry is upper bounded by the (tight) bound
        // entry < 2**39 + 2 **37 - 159
        // In particular `entry` is bounded by modulus and hence we can call Felt::from_mont on each limb before combining
        //result[r] = Felt::from_mont(state_h[r]) * TWO_POWER_32 + Felt::from_mont(state_l[r]);

        // Solution 3: perform the multiplication by 2^32 before calling from_mont on the limbs
        // ================================================================================================

        // Let x = state_h[r], then x = u * R mod p where R = 2**64 mod p.
        // On the other hand 2**32 * R = 2**64 * 2**32 = (2**32 - 1) * 2**32 = 2**64 - 2**32 = -1 (mod p)
        // and hence 2**32 = -R^(-1) mod p
        // Combining the above, this means that x * 2**32 = u * R * (-R^(-1)) = - u (mod p)
        // In other words, multiplying by 2**32 is equivalent to mapping Montgomery form to canonical one
        // and then negating.
        // result[r] = Felt::from_mont(state_l[r]) - Felt::from_mont(Felt::from_mont(state_h[r]).as_int());
    }
    *state = result;
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
