// CONSTANTS / COLUMN FAMILY NAMES
// ================================================================================================

pub(super) const LEAVES_CF: &str = "v1/leaves";
pub(super) const METADATA_CF: &str = "v1/metadata";

pub(super) const SUBTREE_00_CF: &str = "v1/st00";
pub(super) const SUBTREE_08_CF: &str = "v1/st08";
pub(super) const SUBTREE_16_CF: &str = "v1/st16";
pub(super) const SUBTREE_24_CF: &str = "v1/st24";
pub(super) const SUBTREE_32_CF: &str = "v1/st32";
pub(super) const SUBTREE_40_CF: &str = "v1/st40";
pub(super) const SUBTREE_48_CF: &str = "v1/st48";
pub(super) const SUBTREE_56_CF: &str = "v1/st56";

pub(super) const SUBTREE_CFS: [&str; 8] = [
    SUBTREE_00_CF,
    SUBTREE_08_CF,
    SUBTREE_16_CF,
    SUBTREE_24_CF,
    SUBTREE_32_CF,
    SUBTREE_40_CF,
    SUBTREE_48_CF,
    SUBTREE_56_CF,
];

#[allow(dead_code)]
pub(super) const ALL_TABLE_NAMES: &[&str] = &[
    LEAVES_CF,
    METADATA_CF,
    SUBTREE_00_CF,
    SUBTREE_08_CF,
    SUBTREE_16_CF,
    SUBTREE_24_CF,
    SUBTREE_32_CF,
    SUBTREE_40_CF,
    SUBTREE_48_CF,
    SUBTREE_56_CF,
];
