use rand_utils::rand_value;

use super::{ALPHA, Felt, FieldElement, INV_ALPHA};

#[test]
fn test_alphas() {
    let e: Felt = Felt::new(rand_value());
    let e_exp = e.exp(ALPHA);
    assert_eq!(e, e_exp.exp(INV_ALPHA));
}
