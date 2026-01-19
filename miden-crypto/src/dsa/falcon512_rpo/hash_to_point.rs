use alloc::vec::Vec;

use p3_field::PrimeField64;

use super::{MODULUS, N, Nonce, Polynomial, Rpo256, ZERO, math::FalconFelt};
use crate::{Felt, Word};

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce using RPO256.
///
/// Note that, in contrast to the SHAKE256-based reference implementation, this implementation
/// does not use rejection sampling but instead uses one of the variants listed in the specification
/// [1]. This variant omits the conditional check in the rejection sampling step at the cost of
/// having to extract 64 bits, instead of 16 bits, of pseudo-randomness. This makes
/// the implementation simpler and constant-time at the cost of a higher number of extracted
/// pseudo-random bits per call to the hash-to-point algorithm.
///
/// [1]: https://falcon-sign.info/falcon.pdf
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
    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    for _ in 0..64 {
        Rpo256::apply_permutation(&mut state);
        state[Rpo256::RATE_RANGE]
            .iter()
            .for_each(|value| coefficients.push(felt_to_falcon_felt(*value)));
    }

    Polynomial::new(coefficients)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a Miden field element to a field element in the prime field with characteristic
/// the Falcon prime.
///
/// Reduces the canonical value of the Miden field element modulo the Falcon prime and
/// converts it to a FalconFelt. The cast to u16 is safe as the Falcon prime (12289) fits in u16.
fn felt_to_falcon_felt(value: Felt) -> FalconFelt {
    FalconFelt::new((value.as_canonical_u64() % MODULUS as u64) as u16)
}
