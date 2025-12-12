#![cfg(feature = "std")]
use p3_field::PrimeCharacteristicRing;

use super::{ALPHA, Felt, INV_ALPHA};
use crate::test_utils::rand_value;

#[test]
fn test_alphas() {
    let e: Felt = Felt::new(rand_value());
    let e_exp = e.exp_u64(ALPHA);
    assert_eq!(e, e_exp.exp_u64(INV_ALPHA));
}
