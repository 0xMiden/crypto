//! Eidos LMCS configuration.

use core::array;

use p3_symmetric::PseudoCompressionFunction;

use super::{
    Eidos,
    framing::{
        compress_packed_u64_block, compress_u64_block, encode_felt_block, encode_packed_felt_block,
        pack_u32_pair_u64,
    },
    primitive::{BlakeG, PACKED_LANES},
};
use crate::{
    Felt,
    stark::{
        hasher::{Alignable, StatefulHasher},
        lmcs::config::LmcsConfig,
    },
};

const DIGEST_WIDTH: usize = super::DIGEST_WIDTH;
const RATE: usize = super::RATE;

const COMPRESSION_INPUTS: usize = 2;

// LMCS creates hasher states with `Default`. Eidos starts from a non-zero
// chaining value, so the state carries one extra flag to mark initialization.
const INIT_FLAG_IDX: usize = DIGEST_WIDTH;
const STATE_WIDTH: usize = DIGEST_WIDTH + 1;

type PackedFelt = [Felt; PACKED_LANES];
type PackedU64 = [u64; PACKED_LANES];
type Digest = [u64; DIGEST_WIDTH];
type PackedDigest = [PackedU64; DIGEST_WIDTH];
type State = [u64; STATE_WIDTH];
type PackedState = [PackedU64; STATE_WIDTH];

/// Eidos LMCS configuration.
pub type EidosLmcs = LmcsConfig<
    PackedFelt,
    PackedU64,
    EidosLmcsHasher,
    EidosLmcsCompressor,
    STATE_WIDTH,
    DIGEST_WIDTH,
>;

/// Stateful hasher used by the Eidos LMCS configuration.
#[derive(Clone, Copy, Debug)]
pub struct EidosLmcsHasher;

/// Compression function used for LMCS internal tree nodes.
#[derive(Clone, Copy, Debug)]
pub struct EidosLmcsCompressor;

impl PseudoCompressionFunction<Digest, COMPRESSION_INPUTS> for EidosLmcsCompressor {
    #[inline]
    fn compress(&self, input: [Digest; COMPRESSION_INPUTS]) -> Digest {
        compress_u64_block([
            input[0][0],
            input[0][1],
            input[0][2],
            input[0][3],
            input[1][0],
            input[1][1],
            input[1][2],
            input[1][3],
        ])
    }
}

impl PseudoCompressionFunction<PackedDigest, COMPRESSION_INPUTS> for EidosLmcsCompressor {
    #[inline]
    fn compress(&self, input: [PackedDigest; COMPRESSION_INPUTS]) -> PackedDigest {
        compress_packed_u64_block([
            input[0][0],
            input[0][1],
            input[0][2],
            input[0][3],
            input[1][0],
            input[1][1],
            input[1][2],
            input[1][3],
        ])
    }
}

impl StatefulHasher<Felt, Digest> for EidosLmcsHasher {
    type State = State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = Felt>) {
        ensure_initialized(state);

        let cv =
            absorb_blocks(unpack_lmcs_cv(&read_digest(state)), input, Felt::ZERO, |cv, block| {
                BlakeG::compress(cv, encode_felt_block(&block))
            });
        pack_lmcs_cv_into(cv, state);
    }

    fn squeeze(&self, state: &Self::State) -> Digest {
        read_digest(state)
    }
}

impl StatefulHasher<PackedFelt, PackedDigest> for EidosLmcsHasher {
    type State = PackedState;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = PackedFelt>) {
        ensure_packed_initialized(state);

        let cv = absorb_blocks(
            unpack_lmcs_cv_packed(&read_digest(state)),
            input,
            [Felt::ZERO; PACKED_LANES],
            |cv, block| BlakeG::compress_packed_native(cv, encode_packed_felt_block(block)),
        );
        pack_lmcs_cv_packed_into(cv, state);
    }

    fn squeeze(&self, state: &Self::State) -> PackedDigest {
        read_digest(state)
    }
}

impl<Input, Target> Alignable<Input, Target> for EidosLmcsHasher {
    // LMCS rows are absorbed in Eidos rate-sized groups; this is independent of
    // the host SIMD lane count.
    const ALIGNMENT: usize = RATE;
}

/// Creates the Eidos LMCS configuration used by the STARK proof config.
pub const fn config() -> EidosLmcs {
    LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor)
}

fn absorb_blocks<T, D>(
    mut digest: D,
    input: impl IntoIterator<Item = T>,
    zero: T,
    mut compress: impl FnMut(D, [T; RATE]) -> D,
) -> D
where
    T: Copy,
{
    let mut block = [zero; RATE];
    let mut filled = 0usize;

    for value in input {
        block[filled] = value;
        filled += 1;

        if filled == RATE {
            digest = compress(digest, block);
            block = [zero; RATE];
            filled = 0;
        }
    }

    if filled != 0 {
        digest = compress(digest, block);
    }

    digest
}

fn ensure_initialized(state: &mut State) {
    if state[INIT_FLAG_IDX] != 0 {
        return;
    }

    write_digest(state, initial_digest());
    state[INIT_FLAG_IDX] = 1;
}

fn ensure_packed_initialized(state: &mut PackedState) {
    let initialized = state[INIT_FLAG_IDX][0] != 0;
    debug_assert!(
        state[INIT_FLAG_IDX].iter().all(|&flag| (flag != 0) == initialized),
        "packed LMCS state contains mixed initialization flags"
    );

    if initialized {
        return;
    }

    let initial = initial_digest();
    for (word, value) in state[..DIGEST_WIDTH].iter_mut().zip(initial) {
        *word = [value; PACKED_LANES];
    }
    state[INIT_FLAG_IDX] = [1; PACKED_LANES];
}

fn initial_digest() -> Digest {
    let initial = Eidos::init_chaining_word(0, 0);
    array::from_fn(|idx| initial[idx].as_canonical_u64())
}

fn read_digest<T: Copy, const WIDTH: usize>(state: &[T; WIDTH]) -> [T; DIGEST_WIDTH] {
    array::from_fn(|idx| state[idx])
}

fn write_digest<T: Copy, const WIDTH: usize>(state: &mut [T; WIDTH], digest: [T; DIGEST_WIDTH]) {
    state[..DIGEST_WIDTH].copy_from_slice(&digest);
}

fn unpack_lmcs_cv(digest: &Digest) -> [u32; 8] {
    let unpack = |value: u64| (value as u32, (value >> 32) as u32);
    let (a, b) = unpack(digest[0]);
    let (c, d) = unpack(digest[1]);
    let (e, f) = unpack(digest[2]);
    let (g, h) = unpack(digest[3]);
    [a, b, c, d, e, f, g, h]
}

fn pack_lmcs_cv_into(cv: [u32; 8], state: &mut State) {
    state[0] = pack_u32_pair_u64(cv[0], cv[1]);
    state[1] = pack_u32_pair_u64(cv[2], cv[3]);
    state[2] = pack_u32_pair_u64(cv[4], cv[5]);
    state[3] = pack_u32_pair_u64(cv[6], cv[7]);
}

fn unpack_lmcs_cv_packed(digest: &PackedDigest) -> [[u32; PACKED_LANES]; 8] {
    let unpack = |value: PackedU64| {
        (
            array::from_fn(|lane| value[lane] as u32),
            array::from_fn(|lane| (value[lane] >> 32) as u32),
        )
    };
    let (a, b) = unpack(digest[0]);
    let (c, d) = unpack(digest[1]);
    let (e, f) = unpack(digest[2]);
    let (g, h) = unpack(digest[3]);
    [a, b, c, d, e, f, g, h]
}

fn pack_lmcs_cv_packed_into(cv: [[u32; PACKED_LANES]; 8], state: &mut PackedState) {
    state[0] = pack_lmcs_pair_packed(cv[0], cv[1]);
    state[1] = pack_lmcs_pair_packed(cv[2], cv[3]);
    state[2] = pack_lmcs_pair_packed(cv[4], cv[5]);
    state[3] = pack_lmcs_pair_packed(cv[6], cv[7]);
}

fn pack_lmcs_pair_packed(lo: [u32; PACKED_LANES], hi: [u32; PACKED_LANES]) -> PackedU64 {
    array::from_fn(|lane| pack_u32_pair_u64(lo[lane], hi[lane]))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_symmetric::PseudoCompressionFunction;

    use super::*;
    use crate::{
        hash::eidos::framing::compress_felt_digest_block,
        stark::hasher::{Alignable, StatefulHasher},
    };

    const INPUT_LENGTHS: [usize; 7] = [0, 1, 7, 8, 9, 16, 17];

    #[test]
    fn lmcs_alignment_is_rate() {
        assert_eq!(<EidosLmcsHasher as Alignable<Felt, Digest>>::ALIGNMENT, RATE);
    }

    #[test]
    fn packed_absorb_matches_scalar_lanes() {
        let hasher = EidosLmcsHasher;

        for len in INPUT_LENGTHS {
            let lanes = scalar_lane_inputs(len);
            let packed_input = pack_lanes(&lanes);

            let mut packed_state = [[0; PACKED_LANES]; STATE_WIDTH];
            <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::absorb_into(
                &hasher,
                &mut packed_state,
                packed_input,
            );

            for lane in 0..PACKED_LANES {
                let mut scalar_state = [0; STATE_WIDTH];
                <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                    &hasher,
                    &mut scalar_state,
                    lanes[lane].iter().copied(),
                );

                for word in 0..STATE_WIDTH {
                    assert_eq!(
                        packed_state[word][lane], scalar_state[word],
                        "packed lane {lane} diverged from scalar at input length {len}, word {word}",
                    );
                }
            }
        }
    }

    #[test]
    fn scalar_absorb_matches_felt_digest_reference() {
        let hasher = EidosLmcsHasher;

        for len in INPUT_LENGTHS {
            let input = scalar_lane_inputs(len)[0].clone();

            let mut state = [0; STATE_WIDTH];
            <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                &hasher,
                &mut state,
                input.iter().copied(),
            );

            let mut expected = Eidos::init_chaining_word(0, 0).into();
            expected = absorb_blocks(expected, input, Felt::ZERO, compress_felt_digest_block);

            let actual = read_digest(&state).map(Felt::new_unchecked);
            assert_eq!(
                actual, expected,
                "LMCS digest changed field semantics at input length {len}",
            );
        }
    }

    #[test]
    fn lmcs_compressor_matches_eidos_merge_semantics() {
        let left = digest_from_seed(10);
        let right = digest_from_seed(20);
        let compressor = EidosLmcsCompressor;

        let actual = compressor.compress([left, right]);
        let expected = eidos_hash_two_digests(left, right);
        assert_eq!(actual, expected);

        let left_packed = pack_digest_lanes(array::from_fn(|lane| digest_from_seed(100 + lane)));
        let right_packed = pack_digest_lanes(array::from_fn(|lane| digest_from_seed(200 + lane)));
        let actual_packed = compressor.compress([left_packed, right_packed]);

        for lane in 0..PACKED_LANES {
            let left_lane = unpack_digest_lane(left_packed, lane);
            let right_lane = unpack_digest_lane(right_packed, lane);
            let expected_lane = eidos_hash_two_digests(left_lane, right_lane);

            for word in 0..DIGEST_WIDTH {
                assert_eq!(
                    actual_packed[word][lane], expected_lane[word],
                    "packed compressor lane {lane} diverged at word {word}",
                );
            }
        }
    }

    fn scalar_lane_inputs(len: usize) -> [Vec<Felt>; PACKED_LANES] {
        array::from_fn(|lane| {
            (0..len)
                .map(|idx| Felt::new_unchecked(1 + lane as u64 * 1_000 + idx as u64))
                .collect()
        })
    }

    fn pack_lanes(lanes: &[Vec<Felt>; PACKED_LANES]) -> Vec<PackedFelt> {
        (0..lanes[0].len()).map(|idx| array::from_fn(|lane| lanes[lane][idx])).collect()
    }

    fn digest_from_seed(seed: usize) -> Digest {
        array::from_fn(|idx| Felt::new_unchecked((seed + idx) as u64).as_canonical_u64())
    }

    fn eidos_hash_two_digests(left: Digest, right: Digest) -> Digest {
        let elements: [Felt; RATE] = array::from_fn(|idx| {
            let value = if idx < DIGEST_WIDTH {
                left[idx]
            } else {
                right[idx - DIGEST_WIDTH]
            };
            Felt::new_unchecked(value)
        });
        let expected: [Felt; DIGEST_WIDTH] = Eidos::hash_elements(&elements).into();
        expected.map(|value| value.as_canonical_u64())
    }

    fn pack_digest_lanes(lanes: [Digest; PACKED_LANES]) -> PackedDigest {
        array::from_fn(|word| array::from_fn(|lane| lanes[lane][word]))
    }

    fn unpack_digest_lane(digest: PackedDigest, lane: usize) -> Digest {
        array::from_fn(|word| digest[word][lane])
    }
}
