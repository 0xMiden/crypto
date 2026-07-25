/// Table name for SMT leaves.
/// Stores `SmtLeaf` data, keyed by their logical u64 index.
pub(super) const LEAVES_CF: &str = "leaves";

/// Table names for SMT subtrees (deep nodes), one per subtree-root depth.
/// Stores serialized `Subtree` data at depth D, keyed by their root `NodeIndex`.
pub(super) const SUBTREE_16_CF: &str = "st16";
pub(super) const SUBTREE_24_CF: &str = "st24";
pub(super) const SUBTREE_32_CF: &str = "st32";
pub(super) const SUBTREE_40_CF: &str = "st40";
pub(super) const SUBTREE_48_CF: &str = "st48";
pub(super) const SUBTREE_56_CF: &str = "st56";

/// Table name for SMT metadata (entry counts).
/// Stores overall SMT metadata such as the current root hash,
/// total leaf count, and total entry count.
pub(super) const METADATA_CF: &str = "metadata";

/// Table name for the in-memory-depth root hash cache used to rebuild the
/// upper part of the tree on startup without deserializing every `st16`
/// subtree blob.
pub(super) const IN_MEM_DEPTH_CF: &str = "in_mem_depth";

/// Key in `METADATA_CF` for the total count of non-empty leaves.
pub(super) const LEAF_COUNT_KEY: &[u8] = b"leaf_count";

/// Key in `METADATA_CF` for the total count of key-value entries.
pub(super) const ENTRY_COUNT_KEY: &[u8] = b"entry_count";
