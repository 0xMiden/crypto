use super::{Felt, StarkField};

// MACROS
// ================================================================================================

/// Construct a new [Word](super::Word) from a hex value.
///
/// Expects a '0x' prefixed hex string followed by up to 64 hex digits.
#[macro_export]
macro_rules! word {
    ($hex:expr) => {{
        let felts: [$crate::Felt; 4] = match $crate::word::parse_hex_string_as_word($hex) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        $crate::Word::new(felts)
    }};
}

/// Parses a hex string into a `[Felt; 4]` array.
pub const fn parse_hex_string_as_word(hex: &str) -> Result<[Felt; 4], &'static str> {
    const fn parse_hex_digit(digit: u8) -> Result<u8, &'static str> {
        match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'A'..=b'F' => Ok(digit - b'A' + 0x0a),
            b'a'..=b'f' => Ok(digit - b'a' + 0x0a),
            _ => Err("Invalid hex character"),
        }
    }
    // Enforce and skip the '0x' prefix.
    let hex_bytes = match hex.as_bytes() {
        [b'0', b'x', rest @ ..] => rest,
        _ => return Err("Hex string must have a \"0x\" prefix"),
    };

    if hex_bytes.len() > 64 {
        return Err("Hex string has more than 64 characters");
    }

    let mut felts = [0u64; 4];
    let mut i = 0;
    while i < hex_bytes.len() {
        let hex_digit = match parse_hex_digit(hex_bytes[i]) {
            // SAFETY: u8 cast to u64 is safe. We cannot use u64::from in const context so we
            // are forced to cast.
            Ok(v) => v as u64,
            Err(e) => return Err(e),
        };

        // This digit's nibble offset within the felt. We need to invert the nibbles per
        // byte for endianness reasons i.e. ABCD -> BADC.
        let inibble = if i.is_multiple_of(2) {
            (i + 1) % 16
        } else {
            (i - 1) % 16
        };

        let value = hex_digit << (inibble * 4);
        felts[i / 2 / 8] += value;

        i += 1;
    }

    // Ensure each felt is within bounds as `Felt::new` silently wraps around.
    // This matches the behavior of `Word::try_from(String)`.
    let mut idx = 0;
    while idx < felts.len() {
        if felts[idx] >= Felt::MODULUS {
            return Err("Felt overflow");
        }
        idx += 1;
    }

    Ok([
        Felt::new(felts[0]),
        Felt::new(felts[1]),
        Felt::new(felts[2]),
        Felt::new(felts[3]),
    ])
}
