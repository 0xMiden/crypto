use alloc::vec::Vec;
use core::ops::Range;

use super::{MODULUS, N, Nonce, Polynomial, Rpo256, ZERO, math::FalconFelt};
use crate::{Felt, Word};

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce using RPO256.
pub fn hash_to_point_rpo256(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
    const STATE_WIDTH: usize = Rpo256::STATE_WIDTH;
    const RATE_RANGE: Range<usize> = Rpo256::RATE_RANGE;

    let mut state = [ZERO; STATE_WIDTH];

    // absorb the nonce into the state
    let nonce_elements = nonce.to_elements();
    for (&n, s) in nonce_elements.iter().zip(state[RATE_RANGE].iter_mut()) {
        *s = n;
    }
    Rpo256::apply_permutation(&mut state);

    // absorb message into the state
    for (&m, s) in message.iter().zip(state[RATE_RANGE].iter_mut()) {
        *s = m;
    }

    // squeeze the coefficients of the polynomial
    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    for _ in 0..(N / STATE_WIDTH) {
        Rpo256::apply_permutation(&mut state);
        state[RATE_RANGE]
            .iter()
            .for_each(|value| coefficients.push(felt_to_falcon_felt(*value)));
    }

    Polynomial::new(coefficients)
}

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce using SHAKE256. This is the hash-to-point algorithm used in the reference implementation.
#[cfg(test)]
pub fn hash_to_point_shake256(message: &[u8], nonce: &Nonce) -> Polynomial<FalconFelt> {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    let mut data = vec![];
    data.extend_from_slice(nonce.as_bytes());
    data.extend_from_slice(message);
    const K: u32 = (1u32 << 16) / MODULUS as u32;

    let mut hasher = Shake256::default();
    hasher.update(&data);
    let mut reader = hasher.finalize_xof();

    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    while coefficients.len() != N {
        let mut randomness = [0u8; 2];
        reader.read(&mut randomness);
        let t = ((randomness[0] as u32) << 8) | (randomness[1] as u32);
        if t < K * MODULUS as u32 {
            coefficients.push(u32_to_falcon_felt(t));
        }
    }

    Polynomial { coefficients }
}

// HELPER FUNCTIONS
// ================================================================================================

fn felt_to_falcon_felt(value: Felt) -> FalconFelt {
    FalconFelt::new((value.as_int() % MODULUS as u64) as i16)
}

#[cfg(test)]
fn u32_to_falcon_felt(value: u32) -> FalconFelt {
    FalconFelt::new((value % MODULUS as u32) as i16)
}
