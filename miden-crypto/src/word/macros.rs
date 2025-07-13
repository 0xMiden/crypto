// MACROS
// ================================================================================================

/// Construct a new [Word](super::Word) from a hex value.
///
/// Expects a '0x' prefixed hex string followed by up to 64 hex digits.
#[macro_export]
macro_rules! word {
    ($hex:expr) => {{
        let word: Word = match $crate::word::Word::parse($hex) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        word
    }};
}
