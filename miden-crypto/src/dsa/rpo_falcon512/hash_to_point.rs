use alloc::vec::Vec;

use num::Zero;

use super::{MODULUS, N, Nonce, Polynomial, Rpo256, ZERO, math::FalconFelt};
use crate::Word;

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce using RPO256.
pub fn hash_to_point_rpo256(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
    let mut state = [ZERO; Rpo256::STATE_WIDTH];

    // absorb the nonce into the state
    let nonce_elements = nonce.to_elements();
    for (&n, s) in nonce_elements.iter().zip(state[Rpo256::RATE_RANGE].iter_mut()) {
        *s = n;
    }
    Rpo256::apply_permutation(&mut state);

    // absorb message into the state
    for (&m, s) in message.iter().zip(state[Rpo256::RATE_RANGE].iter_mut()) {
        *s = m;
    }

    // squeeze the coefficients of the polynomial
    let mut i = 0;
    let mut res = [FalconFelt::zero(); N];
    for _ in 0..64 {
        Rpo256::apply_permutation(&mut state);
        for a in &state[Rpo256::RATE_RANGE] {
            res[i] = FalconFelt::new((a.as_int() % MODULUS as u64) as i16);
            i += 1;
        }
    }

    Polynomial::new(res.to_vec())
}

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce using SHAKE256. This is the hash-to-point algorithm used in the reference implementation.
#[allow(dead_code)]
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
            coefficients.push(FalconFelt::new((t % MODULUS as u32) as i16));
        }
    }

    Polynomial { coefficients }
}
