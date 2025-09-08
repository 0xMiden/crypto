use core::ops::Range;

use super::{Felt, Hasher, ZERO};
use lazy_static::lazy_static;
mod arch;
pub use arch::optimized::{add_constants_and_apply_inv_sbox, add_constants_and_apply_sbox};

mod mds;
use mds::apply_mds;

mod rpo;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
pub use rpo::{Rpo256, RpoDigest, RpoDigestError, RpoHasher, RpoChallenger, RpoCompression, RpoPermutation256};

mod rpx;
pub use rpx::{Rpx256, RpxDigest, RpxDigestError};

#[cfg(test)]
mod tests;

type CubeExtension = BinomialExtensionField<Felt, 5>;



// CONSTANTS
// ================================================================================================

/// The number of rounds is set to 7. For the RPO hash functions all rounds are uniform. For the
/// RPX hash function, there are 3 different types of rounds.
const NUM_ROUNDS: usize = 7;

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of bytes needed to encoded a digest
const DIGEST_BYTES: usize = 32;

/// The number of byte chunks defining a field element when hashing a sequence of bytes
const BINARY_CHUNK_SIZE: usize = 7;

/// S-Box and Inverse S-Box powers;
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

// SBOX FUNCTION
// ================================================================================================

#[inline(always)]
fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
    state[0] = state[0].exp_u64(7);
    state[1] = state[1].exp_u64(7);
    state[2] = state[2].exp_u64(7);
    state[3] = state[3].exp_u64(7);
    state[4] = state[4].exp_u64(7);
    state[5] = state[5].exp_u64(7);
    state[6] = state[6].exp_u64(7);
    state[7] = state[7].exp_u64(7);
    state[8] = state[8].exp_u64(7);
    state[9] = state[9].exp_u64(7);
    state[10] = state[10].exp_u64(7);
    state[11] = state[11].exp_u64(7);
}

// INVERSE SBOX FUNCTION
// ================================================================================================

#[inline(always)]
fn apply_inv_sbox(state: &mut [Felt; STATE_WIDTH]) {
    // compute base^10540996611094048183 using 72 multiplications per array element
    // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

    // compute base^10
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    // compute base^100
    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    // compute base^100100
    let t3 = exp_acc::<Felt, STATE_WIDTH, 3>(t2, t2);

    // compute base^100100100100
    let t4 = exp_acc::<Felt, STATE_WIDTH, 6>(t3, t3);

    // compute base^100100100100100100100100
    let t5 = exp_acc::<Felt, STATE_WIDTH, 12>(t4, t4);

    // compute base^100100100100100100100100100100
    let t6 = exp_acc::<Felt, STATE_WIDTH, 6>(t5, t3);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    let t7 = exp_acc::<Felt, STATE_WIDTH, 31>(t6, t6);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    for (i, s) in state.iter_mut().enumerate() {
        let a = (t7[i].square() * t6[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }

    #[inline(always)]
    fn exp_acc<B: Field, const N: usize, const M: usize>(
        base: [B; N],
        tail: [B; N],
    ) -> [B; N] {
        let mut result = base;
        for _ in 0..M {
            result.iter_mut().for_each(|r| *r = r.square());
        }
        result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
        result
    }
}

#[inline(always)]
fn add_constants(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; STATE_WIDTH]) {
    state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
}

// ROUND CONSTANTS
// ================================================================================================


lazy_static!{
/// Rescue round constants;
/// computed as in [specifications](https://github.com/ASDiscreteMathematics/rpo)
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of RPO round, and ARK2 contains constants for the second half of RPO round.
/// 

    static ref ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::from_u64(5789762306288267392),
        Felt::from_u64(6522564764413701783),
        Felt::from_u64(17809893479458208203),
        Felt::from_u64(107145243989736508),
        Felt::from_u64(6388978042437517382),
        Felt::from_u64(15844067734406016715),
        Felt::from_u64(9975000513555218239),
        Felt::from_u64(3344984123768313364),
        Felt::from_u64(9959189626657347191),
        Felt::from_u64(12960773468763563665),
        Felt::from_u64(9602914297752488475),
        Felt::from_u64(16657542370200465908),
    ],
    [
        Felt::from_u64(12987190162843096997),
        Felt::from_u64(653957632802705281),
        Felt::from_u64(4441654670647621225),
        Felt::from_u64(4038207883745915761),
        Felt::from_u64(5613464648874830118),
        Felt::from_u64(13222989726778338773),
        Felt::from_u64(3037761201230264149),
        Felt::from_u64(16683759727265180203),
        Felt::from_u64(8337364536491240715),
        Felt::from_u64(3227397518293416448),
        Felt::from_u64(8110510111539674682),
        Felt::from_u64(2872078294163232137),
    ],
    [
        Felt::from_u64(18072785500942327487),
        Felt::from_u64(6200974112677013481),
        Felt::from_u64(17682092219085884187),
        Felt::from_u64(10599526828986756440),
        Felt::from_u64(975003873302957338),
        Felt::from_u64(8264241093196931281),
        Felt::from_u64(10065763900435475170),
        Felt::from_u64(2181131744534710197),
        Felt::from_u64(6317303992309418647),
        Felt::from_u64(1401440938888741532),
        Felt::from_u64(8884468225181997494),
        Felt::from_u64(13066900325715521532),
    ],
    [
        Felt::from_u64(5674685213610121970),
        Felt::from_u64(5759084860419474071),
        Felt::from_u64(13943282657648897737),
        Felt::from_u64(1352748651966375394),
        Felt::from_u64(17110913224029905221),
        Felt::from_u64(1003883795902368422),
        Felt::from_u64(4141870621881018291),
        Felt::from_u64(8121410972417424656),
        Felt::from_u64(14300518605864919529),
        Felt::from_u64(13712227150607670181),
        Felt::from_u64(17021852944633065291),
        Felt::from_u64(6252096473787587650),
    ],
    [
        Felt::from_u64(4887609836208846458),
        Felt::from_u64(3027115137917284492),
        Felt::from_u64(9595098600469470675),
        Felt::from_u64(10528569829048484079),
        Felt::from_u64(7864689113198939815),
        Felt::from_u64(17533723827845969040),
        Felt::from_u64(5781638039037710951),
        Felt::from_u64(17024078752430719006),
        Felt::from_u64(109659393484013511),
        Felt::from_u64(7158933660534805869),
        Felt::from_u64(2955076958026921730),
        Felt::from_u64(7433723648458773977),
    ],
    [
        Felt::from_u64(16308865189192447297),
        Felt::from_u64(11977192855656444890),
        Felt::from_u64(12532242556065780287),
        Felt::from_u64(14594890931430968898),
        Felt::from_u64(7291784239689209784),
        Felt::from_u64(5514718540551361949),
        Felt::from_u64(10025733853830934803),
        Felt::from_u64(7293794580341021693),
        Felt::from_u64(6728552937464861756),
        Felt::from_u64(6332385040983343262),
        Felt::from_u64(13277683694236792804),
        Felt::from_u64(2600778905124452676),
    ],
    [
        Felt::from_u64(7123075680859040534),
        Felt::from_u64(1034205548717903090),
        Felt::from_u64(7717824418247931797),
        Felt::from_u64(3019070937878604058),
        Felt::from_u64(11403792746066867460),
        Felt::from_u64(10280580802233112374),
        Felt::from_u64(337153209462421218),
        Felt::from_u64(13333398568519923717),
        Felt::from_u64(3596153696935337464),
        Felt::from_u64(8104208463525993784),
        Felt::from_u64(14345062289456085693),
        Felt::from_u64(17036731477169661256),
    ],
    ];
}

lazy_static!{
    static ref ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::from_u64(6077062762357204287),
        Felt::from_u64(15277620170502011191),
        Felt::from_u64(5358738125714196705),
        Felt::from_u64(14233283787297595718),
        Felt::from_u64(13792579614346651365),
        Felt::from_u64(11614812331536767105),
        Felt::from_u64(14871063686742261166),
        Felt::from_u64(10148237148793043499),
        Felt::from_u64(4457428952329675767),
        Felt::from_u64(15590786458219172475),
        Felt::from_u64(10063319113072092615),
        Felt::from_u64(14200078843431360086),
    ],
    [
        Felt::from_u64(6202948458916099932),
        Felt::from_u64(17690140365333231091),
        Felt::from_u64(3595001575307484651),
        Felt::from_u64(373995945117666487),
        Felt::from_u64(1235734395091296013),
        Felt::from_u64(14172757457833931602),
        Felt::from_u64(707573103686350224),
        Felt::from_u64(15453217512188187135),
        Felt::from_u64(219777875004506018),
        Felt::from_u64(17876696346199469008),
        Felt::from_u64(17731621626449383378),
        Felt::from_u64(2897136237748376248),
    ],
    [
        Felt::from_u64(8023374565629191455),
        Felt::from_u64(15013690343205953430),
        Felt::from_u64(4485500052507912973),
        Felt::from_u64(12489737547229155153),
        Felt::from_u64(9500452585969030576),
        Felt::from_u64(2054001340201038870),
        Felt::from_u64(12420704059284934186),
        Felt::from_u64(355990932618543755),
        Felt::from_u64(9071225051243523860),
        Felt::from_u64(12766199826003448536),
        Felt::from_u64(9045979173463556963),
        Felt::from_u64(12934431667190679898),
    ],
    [
        Felt::from_u64(18389244934624494276),
        Felt::from_u64(16731736864863925227),
        Felt::from_u64(4440209734760478192),
        Felt::from_u64(17208448209698888938),
        Felt::from_u64(8739495587021565984),
        Felt::from_u64(17000774922218161967),
        Felt::from_u64(13533282547195532087),
        Felt::from_u64(525402848358706231),
        Felt::from_u64(16987541523062161972),
        Felt::from_u64(5466806524462797102),
        Felt::from_u64(14512769585918244983),
        Felt::from_u64(10973956031244051118),
    ],
    [
        Felt::from_u64(6982293561042362913),
        Felt::from_u64(14065426295947720331),
        Felt::from_u64(16451845770444974180),
        Felt::from_u64(7139138592091306727),
        Felt::from_u64(9012006439959783127),
        Felt::from_u64(14619614108529063361),
        Felt::from_u64(1394813199588124371),
        Felt::from_u64(4635111139507788575),
        Felt::from_u64(16217473952264203365),
        Felt::from_u64(10782018226466330683),
        Felt::from_u64(6844229992533662050),
        Felt::from_u64(7446486531695178711),
    ],
    [
        Felt::from_u64(3736792340494631448),
        Felt::from_u64(577852220195055341),
        Felt::from_u64(6689998335515779805),
        Felt::from_u64(13886063479078013492),
        Felt::from_u64(14358505101923202168),
        Felt::from_u64(7744142531772274164),
        Felt::from_u64(16135070735728404443),
        Felt::from_u64(12290902521256031137),
        Felt::from_u64(12059913662657709804),
        Felt::from_u64(16456018495793751911),
        Felt::from_u64(4571485474751953524),
        Felt::from_u64(17200392109565783176),
    ],
    [
        Felt::from_u64(17130398059294018733),
        Felt::from_u64(519782857322261988),
        Felt::from_u64(9625384390925085478),
        Felt::from_u64(1664893052631119222),
        Felt::from_u64(7629576092524553570),
        Felt::from_u64(3485239601103661425),
        Felt::from_u64(9755891797164033838),
        Felt::from_u64(15218148195153269027),
        Felt::from_u64(16460604813734957368),
        Felt::from_u64(9643968136937729763),
        Felt::from_u64(3611348709641382851),
        Felt::from_u64(18256379591337759196),
    ],
    ];
}