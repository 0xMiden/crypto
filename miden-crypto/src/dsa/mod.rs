//! Digital signature schemes supported by default in the Miden VM.

use core::fmt;

pub mod ecdsa_k256_keccak;
pub mod eddsa_25519_sha512;
pub mod falcon512_poseidon2;

/// Writes `bytes` into the formatter as a `0x`-prefixed, lowercase hexadecimal string.
///
/// Shared by the `Display` implementations of the public key and signature types across the
/// supported signature schemes, so that `%`-formatting (e.g. in `tracing` logs) produces compact,
/// canonical output that is easy to compare across nodes. This mirrors the format produced by
/// [`crate::utils::bytes_to_hex_string`], which only accepts fixed-size arrays.
pub(crate) fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    write!(f, "0x")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
