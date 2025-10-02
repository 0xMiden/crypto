use super::{Felt, STATE_WIDTH};

// HASH FUNCTION DEFINING CONSTANTS
// ================================================================================================

/// Number of external rounds.
pub(crate) const NUM_EXTERNAL_ROUNDS: usize = 8;
/// Number of either initial or terminal external rounds.
pub(crate) const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS / 2;
/// Number of internal rounds.
pub(crate) const NUM_INTERNAL_ROUNDS: usize = 22;

// DIAGONAL MATRIX USED IN INTERNAL ROUNDS
// ================================================================================================

pub(crate) const MAT_DIAG: [Felt; STATE_WIDTH] = [
    Felt::from_u64(0xc3b6c08e23ba9300),
    Felt::from_u64(0xd84b5de94a324fb6),
    Felt::from_u64(0x0d0c371c5b35b84f),
    Felt::from_u64(0x7964f570e7188037),
    Felt::from_u64(0x5daf18bbd996604b),
    Felt::from_u64(0x6743bc47b9595257),
    Felt::from_u64(0x5528b9362c59bb70),
    Felt::from_u64(0xac45e25b7127b68b),
    Felt::from_u64(0xa2077d7dfbb606b5),
    Felt::from_u64(0xf3faac6faee378ae),
    Felt::from_u64(0x0c6388b51545e883),
    Felt::from_u64(0xd27dbb6944917b60),
];

// ROUND CONSTANTS
// ================================================================================================

pub(crate) const ARK_EXT_INITIAL: [[Felt; 12]; 4] = [
    [
        Felt::from_u64(0x13dcf33aba214f46),
        Felt::from_u64(0x30b3b654a1da6d83),
        Felt::from_u64(0x1fc634ada6159b56),
        Felt::from_u64(0x937459964dc03466),
        Felt::from_u64(0xedd2ef2ca7949924),
        Felt::from_u64(0xede9affde0e22f68),
        Felt::from_u64(0x8515b9d6bac9282d),
        Felt::from_u64(0x6b5c07b4e9e900d8),
        Felt::from_u64(0x1ec66368838c8a08),
        Felt::from_u64(0x9042367d80d1fbab),
        Felt::from_u64(0x400283564a3c3799),
        Felt::from_u64(0x4a00be0466bca75e),
    ],
    [
        Felt::from_u64(0x7913beee58e3817f),
        Felt::from_u64(0xf545e88532237d90),
        Felt::from_u64(0x22f8cb8736042005),
        Felt::from_u64(0x6f04990e247a2623),
        Felt::from_u64(0xfe22e87ba37c38cd),
        Felt::from_u64(0xd20e32c85ffe2815),
        Felt::from_u64(0x117227674048fe73),
        Felt::from_u64(0x4e9fb7ea98a6b145),
        Felt::from_u64(0xe0866c232b8af08b),
        Felt::from_u64(0x00bbc77916884964),
        Felt::from_u64(0x7031c0fb990d7116),
        Felt::from_u64(0x240a9e87cf35108f),
    ],
    [
        Felt::from_u64(0x2e6363a5a12244b3),
        Felt::from_u64(0x5e1c3787d1b5011c),
        Felt::from_u64(0x4132660e2a196e8b),
        Felt::from_u64(0x3a013b648d3d4327),
        Felt::from_u64(0xf79839f49888ea43),
        Felt::from_u64(0xfe85658ebafe1439),
        Felt::from_u64(0xb6889825a14240bd),
        Felt::from_u64(0x578453605541382b),
        Felt::from_u64(0x4508cda8f6b63ce9),
        Felt::from_u64(0x9c3ef35848684c91),
        Felt::from_u64(0x0812bde23c87178c),
        Felt::from_u64(0xfe49638f7f722c14),
    ],
    [
        Felt::from_u64(0x8e3f688ce885cbf5),
        Felt::from_u64(0xb8e110acf746a87d),
        Felt::from_u64(0xb4b2e8973a6dabef),
        Felt::from_u64(0x9e714c5da3d462ec),
        Felt::from_u64(0x6438f9033d3d0c15),
        Felt::from_u64(0x24312f7cf1a27199),
        Felt::from_u64(0x23f843bb47acbf71),
        Felt::from_u64(0x9183f11a34be9f01),
        Felt::from_u64(0x839062fbb9d45dbf),
        Felt::from_u64(0x24b56e7e6c2e43fa),
        Felt::from_u64(0xe1683da61c962a72),
        Felt::from_u64(0xa95c63971a19bfa7),
    ],
];

pub(crate) const ARK_INT: [Felt; 22] = [
    Felt::from_u64(0x4adf842aa75d4316),
    Felt::from_u64(0xf8fbb871aa4ab4eb),
    Felt::from_u64(0x68e85b6eb2dd6aeb),
    Felt::from_u64(0x07a0b06b2d270380),
    Felt::from_u64(0xd94e0228bd282de4),
    Felt::from_u64(0x8bdd91d3250c5278),
    Felt::from_u64(0x209c68b88bba778f),
    Felt::from_u64(0xb5e18cdab77f3877),
    Felt::from_u64(0xb296a3e808da93fa),
    Felt::from_u64(0x8370ecbda11a327e),
    Felt::from_u64(0x3f9075283775dad8),
    Felt::from_u64(0xb78095bb23c6aa84),
    Felt::from_u64(0x3f36b9fe72ad4e5f),
    Felt::from_u64(0x69bc96780b10b553),
    Felt::from_u64(0x3f1d341f2eb7b881),
    Felt::from_u64(0x4e939e9815838818),
    Felt::from_u64(0xda366b3ae2a31604),
    Felt::from_u64(0xbc89db1e7287d509),
    Felt::from_u64(0x6102f411f9ef5659),
    Felt::from_u64(0x58725c5e7ac1f0ab),
    Felt::from_u64(0x0df5856c798883e7),
    Felt::from_u64(0xf7bb62a8da4c961b),
];

pub(crate) const ARK_EXT_TERMINAL: [[Felt; STATE_WIDTH]; 4] = [
    [
        Felt::from_u64(0xc68be7c94882a24d),
        Felt::from_u64(0xaf996d5d5cdaedd9),
        Felt::from_u64(0x9717f025e7daf6a5),
        Felt::from_u64(0x6436679e6e7216f4),
        Felt::from_u64(0x8a223d99047af267),
        Felt::from_u64(0xbb512e35a133ba9a),
        Felt::from_u64(0xfbbf44097671aa03),
        Felt::from_u64(0xf04058ebf6811e61),
        Felt::from_u64(0x5cca84703fac7ffb),
        Felt::from_u64(0x9b55c7945de6469f),
        Felt::from_u64(0x8e05bf09808e934f),
        Felt::from_u64(0x2ea900de876307d7),
    ],
    [
        Felt::from_u64(0x7748fff2b38dfb89),
        Felt::from_u64(0x6b99a676dd3b5d81),
        Felt::from_u64(0xac4bb7c627cf7c13),
        Felt::from_u64(0xadb6ebe5e9e2f5ba),
        Felt::from_u64(0x2d33378cafa24ae3),
        Felt::from_u64(0x1e5b73807543f8c2),
        Felt::from_u64(0x09208814bfebb10f),
        Felt::from_u64(0x782e64b6bb5b93dd),
        Felt::from_u64(0xadd5a48eac90b50f),
        Felt::from_u64(0xadd4c54c736ea4b1),
        Felt::from_u64(0xd58dbb86ed817fd8),
        Felt::from_u64(0x6d5ed1a533f34ddd),
    ],
    [
        Felt::from_u64(0x28686aa3e36b7cb9),
        Felt::from_u64(0x591abd3476689f36),
        Felt::from_u64(0x047d766678f13875),
        Felt::from_u64(0xa2a11112625f5b49),
        Felt::from_u64(0x21fd10a3f8304958),
        Felt::from_u64(0xf9b40711443b0280),
        Felt::from_u64(0xd2697eb8b2bde88e),
        Felt::from_u64(0x3493790b51731b3f),
        Felt::from_u64(0x11caf9dd73764023),
        Felt::from_u64(0x7acfb8f72878164e),
        Felt::from_u64(0x744ec4db23cefc26),
        Felt::from_u64(0x1e00e58f422c6340),
    ],
    [
        Felt::from_u64(0x21dd28d906a62dda),
        Felt::from_u64(0xf32a46ab5f465b5f),
        Felt::from_u64(0xbfce13201f3f7e6b),
        Felt::from_u64(0xf30d2e7adb5304e2),
        Felt::from_u64(0xecdf4ee4abad48e9),
        Felt::from_u64(0xf94e82182d395019),
        Felt::from_u64(0x4ee52e3744d887c5),
        Felt::from_u64(0xa1341c7cac0083b2),
        Felt::from_u64(0x2302fb26c30c834a),
        Felt::from_u64(0xaea3c587273bf7d3),
        Felt::from_u64(0xf798e24961823ec7),
        Felt::from_u64(0x962deba3e9a2cd94),
    ],
];
