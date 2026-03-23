//! STARK configuration helpers for **BLAKE3** with a **32-byte** digest (Plonky3 [`p3_blake3::Blake3`]).
//!
//! Same LMCS pattern as [`crate::blake3_192`], but `WIDTH` / `DIGEST` are 32 bytes to match the
//! standard BLAKE3 output length used with the compression AIR in `p3-blake3-air`.

pub mod goldilocks {
    use alloc::vec::Vec;

    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger64};
    use p3_field::extension::BinomialExtensionField;
    use p3_goldilocks::Goldilocks;
    use p3_miden_stateful_hasher::ChainingHasher;
    use p3_symmetric::CompressionFunctionFromHasher;

    use crate::lmcs::LmcsConfig;

    pub type F = Goldilocks;
    pub type EF = BinomialExtensionField<F, 2>;

    pub const WIDTH: usize = 32;
    pub const DIGEST: usize = 32;

    pub type Sponge = ChainingHasher<Blake3>;
    pub type Compress = CompressionFunctionFromHasher<Blake3, 2, DIGEST>;
    pub type Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
    pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, DIGEST>>;

    pub fn lmcs() -> Lmcs {
        LmcsConfig::new(
            ChainingHasher::new(Blake3),
            CompressionFunctionFromHasher::new(Blake3),
        )
    }

    pub fn challenger() -> Challenger {
        SerializingChallenger64::from_hasher(Vec::new(), Blake3)
    }
}

pub mod baby_bear {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger64};
    use p3_field::extension::BinomialExtensionField;
    use p3_miden_stateful_hasher::ChainingHasher;
    use p3_symmetric::CompressionFunctionFromHasher;

    use crate::lmcs::LmcsConfig;

    pub type F = BabyBear;
    pub type EF = BinomialExtensionField<F, 4>;

    pub const WIDTH: usize = 32;
    pub const DIGEST: usize = 32;

    pub type Sponge = ChainingHasher<Blake3>;
    pub type Compress = CompressionFunctionFromHasher<Blake3, 2, DIGEST>;
    pub type Lmcs = LmcsConfig<F, u8, Sponge, Compress, WIDTH, DIGEST>;
    pub type Challenger = SerializingChallenger64<F, HashChallenger<u8, Blake3, DIGEST>>;

    pub fn lmcs() -> Lmcs {
        LmcsConfig::new(
            ChainingHasher::new(Blake3),
            CompressionFunctionFromHasher::new(Blake3),
        )
    }

    pub fn challenger() -> Challenger {
        SerializingChallenger64::from_hasher(Vec::new(), Blake3)
    }
}
