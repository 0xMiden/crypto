//! Shared utilities for LMCS benchmarks.

use p3_blake3::Blake3;
use p3_keccak::KeccakF;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::{
    goldilocks_blake3_192 as gl_blake3_192, goldilocks_keccak as gl_keccak,
    goldilocks_poseidon2 as gl,
};
use p3_miden_lmcs::testing::{
    goldilocks_blake3_192 as gl_blake3_192_lmcs, goldilocks_keccak as gl_keccak_lmcs,
};
use p3_symmetric::{PaddingFreeSponge, SerializingHasher};

// =============================================================================
// Poseidon2 MMCS types (for comparison benchmarks)
// =============================================================================

type GoldilocksMmcsSponge =
    PaddingFreeSponge<gl::Perm, { gl::WIDTH }, { gl::RATE }, { gl::DIGEST }>;
type GoldilocksMmcs =
    MerkleTreeMmcs<gl::P, gl::P, GoldilocksMmcsSponge, gl::Compress, 2, { gl::DIGEST }>;

pub fn gl_poseidon2_mmcs() -> GoldilocksMmcs {
    let perm = gl::create_perm();
    GoldilocksMmcs::new(
        GoldilocksMmcsSponge::new(perm.clone()),
        gl::Compress::new(perm),
        0,
    )
}

// =============================================================================
// Keccak LMCS (from testing module)
// =============================================================================

pub fn gl_keccak_lmcs() -> gl_keccak_lmcs::Lmcs {
    gl_keccak_lmcs::test_lmcs()
}

// =============================================================================
// Keccak MMCS types (for comparison benchmarks)
// =============================================================================

type GoldilocksKeccakMmcs = MerkleTreeMmcs<
    gl_keccak::F,
    u64,
    SerializingHasher<gl_keccak::KeccakMmcsSponge>,
    gl_keccak::Compress,
    2,
    { gl_keccak::DIGEST },
>;

pub fn gl_keccak_mmcs() -> GoldilocksKeccakMmcs {
    let inner = gl_keccak::KeccakMmcsSponge::new(KeccakF);
    GoldilocksKeccakMmcs::new(
        SerializingHasher::new(inner),
        gl_keccak::Compress::new(inner),
        0,
    )
}

// =============================================================================
// Blake3-192 LMCS (from testing module)
// =============================================================================

pub fn gl_blake3_192_lmcs() -> gl_blake3_192_lmcs::Lmcs {
    gl_blake3_192_lmcs::test_lmcs()
}

// =============================================================================
// Blake3-192 MMCS types (for comparison benchmarks)
// =============================================================================

type GoldilocksBlake3_192Mmcs = MerkleTreeMmcs<
    gl_blake3_192::F,
    u8,
    SerializingHasher<gl_blake3_192::Blake3_192>,
    gl_blake3_192::Compress,
    2,
    { gl_blake3_192::DIGEST },
>;

pub fn gl_blake3_192_mmcs() -> GoldilocksBlake3_192Mmcs {
    let inner = gl_blake3_192::Blake3_192::new(Blake3);
    GoldilocksBlake3_192Mmcs::new(
        SerializingHasher::new(inner),
        gl_blake3_192::Compress::new(inner),
        0,
    )
}
