use p3_field::PrimeCharacteristicRing;
use rand_utils::rand_value;

use super::{ALPHA, Felt, INV_ALPHA};

#[test]
fn test_alphas() {
    let e: Felt = Felt::new(rand_value());
    let e_exp = e.exp_u64(ALPHA);
    assert_eq!(e, e_exp.exp_u64(INV_ALPHA));
}
