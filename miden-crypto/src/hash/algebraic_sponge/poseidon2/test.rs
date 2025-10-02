use super::{Felt, ZERO};
use crate::hash::{algebraic_sponge::AlgebraicSponge, poseidon2::Poseidon2};

#[test]
fn permutation_test_vector() {
    // tests that the current implementation is consistent with
    // the reference [implementation](https://github.com/HorizenLabs/poseidon2) and uses
    // the test vectors provided therein
    let mut elements = [
        ZERO,
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
        Felt::new(9),
        Felt::new(10),
        Felt::new(11),
    ];

    Poseidon2::apply_permutation(&mut elements);
    let perm = elements;
    assert_eq!(perm[0], Felt::new(0x01eaef96bdf1c0c1));
    assert_eq!(perm[1], Felt::new(0x1f0d2cc525b2540c));
    assert_eq!(perm[2], Felt::new(0x6282c1dfe1e0358d));
    assert_eq!(perm[3], Felt::new(0xe780d721f698e1e6));
    assert_eq!(perm[4], Felt::new(0x280c0b6f753d833b));
    assert_eq!(perm[5], Felt::new(0x1b942dd5023156ab));
    assert_eq!(perm[6], Felt::new(0x43f0df3fcccb8398));
    assert_eq!(perm[7], Felt::new(0xe8e8190585489025));
    assert_eq!(perm[8], Felt::new(0x56bdbf72f77ada22));
    assert_eq!(perm[9], Felt::new(0x7911c32bf9dcd705));
    assert_eq!(perm[10], Felt::new(0xec467926508fbe67));
    assert_eq!(perm[11], Felt::new(0x6a50450ddf85a6ed));
}
