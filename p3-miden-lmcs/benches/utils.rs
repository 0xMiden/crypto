//! Shared utilities for LMCS benchmarks.

use p3_keccak::{KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_dev_utils::configs::{goldilocks_keccak as gl_keccak, goldilocks_poseidon2 as gl};
use p3_miden_lmcs::LmcsConfig;
use p3_miden_stateful_hasher::{SerializingStatefulSponge, StatefulSponge};
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
// Keccak LMCS types
// =============================================================================

type KeccakStatefulSponge = StatefulSponge<KeccakF, 25, 17, 4>;

/// Keccak LMCS for Goldilocks field.
///
/// Uses `[F; VECTOR_LEN]` for field elements and `[u64; VECTOR_LEN]` for digest elements,
/// enabling SIMD parallelization where `VECTOR_LEN` is platform-specific (1, 2, 4, or 8).
pub type GoldilocksKeccakLmcs = LmcsConfig<
    [gl_keccak::F; VECTOR_LEN],
    [u64; VECTOR_LEN],
    SerializingStatefulSponge<KeccakStatefulSponge>,
    gl_keccak::KeccakCompress,
    25,
    4,
>;

// =============================================================================
// Keccak MMCS types (for comparison benchmarks)
// =============================================================================

type GoldilocksKeccakMmcs = MerkleTreeMmcs<
    gl_keccak::F,
    u64,
    SerializingHasher<gl_keccak::KeccakMmcsSponge>,
    gl_keccak::KeccakCompress,
    2,
    { gl_keccak::DIGEST },
>;

// =============================================================================
// Keccak constructors
// =============================================================================

fn keccak_sponge() -> SerializingStatefulSponge<KeccakStatefulSponge> {
    SerializingStatefulSponge::new(StatefulSponge::new(KeccakF {}))
}

pub fn gl_keccak_lmcs() -> GoldilocksKeccakLmcs {
    let inner = gl_keccak::KeccakMmcsSponge::new(KeccakF {});
    let compress = gl_keccak::KeccakCompress::new(inner);
    LmcsConfig::new(keccak_sponge(), compress)
}

pub fn gl_keccak_mmcs() -> GoldilocksKeccakMmcs {
    let inner = gl_keccak::KeccakMmcsSponge::new(KeccakF {});
    GoldilocksKeccakMmcs::new(
        SerializingHasher::new(inner),
        gl_keccak::KeccakCompress::new(inner),
        0,
    )
}
