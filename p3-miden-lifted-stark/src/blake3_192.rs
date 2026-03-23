//! STARK configuration helpers for **BLAKE3 with a 24-byte digest** (~96-bit collision resistance).
//!
//! Use [`goldilocks`](`crate::blake3_192::goldilocks`) or [`baby_bear`](`crate::blake3_192::baby_bear`)
//! with [`crate::GenericStarkConfig`] the same way as Poseidon2-based dev configs, but with byte LMCS
//! (`LmcsConfig<F, u8, …>`).

pub mod goldilocks {
    use alloc::vec::Vec;

    use p3_challenger::{HashChallenger, SerializingChallenger64};
    use p3_field::extension::BinomialExtensionField;
    use p3_goldilocks::Goldilocks;
    use p3_miden_blake3::Blake3_192;
    use p3_miden_stateful_hasher::ChainingHasher;
    use p3_symmetric::CompressionFunctionFromHasher;

    use crate::lmcs::LmcsConfig;

    pub type F = Goldilocks;
    pub type EF = BinomialExtensionField<F, 2>;

    pub const WIDTH: usize = 24;
    pub const DIGEST: usize = 24;

    pub type Sponge = ChainingHasher<Blake3_192>;
    pub type Compress = CompressionFunctionFromHasher<Blake3_192, 2, DIGEST>;
    pub type Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
    pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3_192, DIGEST>>;

    pub fn lmcs() -> Lmcs {
        LmcsConfig::new(
            ChainingHasher::new(Blake3_192),
            CompressionFunctionFromHasher::new(Blake3_192),
        )
    }

    pub fn challenger() -> Challenger {
        SerializingChallenger64::new(HashChallenger::new(Vec::new(), Blake3_192))
    }
}

pub mod baby_bear {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger64};
    use p3_field::extension::BinomialExtensionField;
    use p3_miden_blake3::Blake3_192;
    use p3_miden_stateful_hasher::ChainingHasher;
    use p3_symmetric::CompressionFunctionFromHasher;

    use crate::lmcs::LmcsConfig;

    pub type F = BabyBear;
    pub type EF = BinomialExtensionField<F, 4>;

    pub const WIDTH: usize = 24;
    pub const DIGEST: usize = 24;

    pub type Sponge = ChainingHasher<Blake3_192>;
    pub type Compress = CompressionFunctionFromHasher<Blake3_192, 2, DIGEST>;
    pub type Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
    pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3_192, DIGEST>>;

    pub fn lmcs() -> Lmcs {
        LmcsConfig::new(
            ChainingHasher::new(Blake3_192),
            CompressionFunctionFromHasher::new(Blake3_192),
        )
    }

    pub fn challenger() -> Challenger {
        SerializingChallenger64::new(HashChallenger::new(Vec::new(), Blake3_192))
    }
}
