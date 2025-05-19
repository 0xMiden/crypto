use alloc::string::String;
use core::{
    cmp::Ordering,
    fmt::Display,
    hash::{Hash, Hasher},
    ops::Deref,
    slice,
};

use thiserror::Error;
use winter_crypto::Digest;

const WORD_SIZE_FELT: usize = 4;
const WORD_SIZE_BYTES: usize = 32;

use super::{Felt, StarkField, ZERO};
use crate::{
    rand::Randomizable,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
        bytes_to_hex_string, hex_to_bytes,
    },
};

// WORD
// ================================================================================================

/// A unit of data consisting of 4 field elements.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
pub struct Word([Felt; WORD_SIZE_FELT]);

impl Word {
    /// The serialized size of the word in bytes.
    pub const SERIALIZED_SIZE: usize = WORD_SIZE_BYTES;

    /// Creates a new [Word] from the given field elements.
    pub const fn new(value: [Felt; WORD_SIZE_FELT]) -> Self {
        Self(value)
    }

    /// Returns the word as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        self.as_ref()
    }

    /// Returns the word as a byte array.
    pub fn as_bytes(&self) -> [u8; WORD_SIZE_BYTES] {
        let mut result = [0; WORD_SIZE_BYTES];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }

    /// Returns an iterator over the elements of multiple words.
    pub(crate) fn words_as_elements_iter<'a, I>(words: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        words.flat_map(|d| d.0.iter())
    }

    /// Returns all elements of multiple words as a slice.
    pub(crate) fn words_as_elements(words: &[Self]) -> &[Felt] {
        let p = words.as_ptr();
        let len = words.len() * WORD_SIZE_FELT;
        unsafe { slice::from_raw_parts(p as *const Felt, len) }
    }

    /// Returns hexadecimal representation of this word prefixed with `0x`.
    pub fn to_hex(&self) -> String {
        bytes_to_hex_string(self.as_bytes())
    }
}

impl Hash for Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl Digest for Word {
    fn as_bytes(&self) -> [u8; WORD_SIZE_BYTES] {
        self.as_bytes()
    }
}

impl Deref for Word {
    type Target = [Felt; WORD_SIZE_FELT];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for Word {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare the inner u64 of both elements.
        //
        // It will iterate the elements and will return the first computation different than
        // `Equal`. Otherwise, the ordering is equal.
        //
        // Finally, we use `Felt::inner` instead of `Felt::as_int` so we avoid performing a
        // montgomery reduction for every limb. That is safe because every inner element of the
        // word is guaranteed to be in its canonical form (that is, `x in [0,p)`).
        //
        // Because we don't perform Montgomery reduction, we must iterate over, and compare,
        // each element. A simple bytestring comparison would be inappropriate because the `Word`s
        // are represented in "lexicographical" order.
        self.0.iter().map(Felt::inner).zip(other.0.iter().map(Felt::inner)).fold(
            Ordering::Equal,
            |ord, (a, b)| match ord {
                Ordering::Equal => a.cmp(&b),
                _ => ord,
            },
        )
    }
}

impl PartialOrd for Word {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Word {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Randomizable for Word {
    const VALUE_SIZE: usize = WORD_SIZE_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: Option<[u8; 32]> = bytes.try_into().ok();
        if let Some(bytes_array) = bytes_array {
            Self::try_from(bytes_array).ok()
        } else {
            None
        }
    }
}

// CONVERSIONS: FROM WORD
// ================================================================================================

/// Errors that can occur when working with a [Word].
#[derive(Debug, Error)]
pub enum WordError {
    /// Failed to convert the word's field elements to the specified type.
    #[error("failed to convert the word's field elements to type {0}")]
    TypeConversion(&'static str),
    /// Field element conversion failed due to invalid value.
    #[error("failed to convert to field element: {0}")]
    InvalidFieldElement(String),
    /// Field elements parsed are out of range.
    #[error("values of a Word must be inside the field modulus")]
    OutOfRange,
    /// Hex-encoded field elements parsed are invalid.
    #[error("hex encoded values of a word are invalid")]
    HexParse(#[from] HexParseError),
}

impl TryFrom<&Word> for [bool; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [bool; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        fn to_bool(v: u64) -> Option<bool> {
            if v <= 1 { Some(v == 1) } else { None }
        }

        Ok([
            to_bool(value.0[0].as_int()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(value.0[1].as_int()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(value.0[2].as_int()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(value.0[3].as_int()).ok_or(WordError::TypeConversion("bool"))?,
        ])
    }
}

impl TryFrom<&Word> for [u8; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u8; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        Ok([
            value.0[0].as_int().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            value.0[1].as_int().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            value.0[2].as_int().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            value.0[3].as_int().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
        ])
    }
}

impl TryFrom<&Word> for [u16; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u16; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        Ok([
            value.0[0].as_int().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            value.0[1].as_int().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            value.0[2].as_int().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            value.0[3].as_int().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
        ])
    }
}

impl TryFrom<&Word> for [u32; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u32; WORD_SIZE_FELT] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        Ok([
            value.0[0].as_int().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            value.0[1].as_int().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            value.0[2].as_int().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            value.0[3].as_int().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
        ])
    }
}

impl From<&Word> for [u64; WORD_SIZE_FELT] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [u64; WORD_SIZE_FELT] {
    fn from(value: Word) -> Self {
        [
            value.0[0].as_int(),
            value.0[1].as_int(),
            value.0[2].as_int(),
            value.0[3].as_int(),
        ]
    }
}

impl From<&Word> for [Felt; WORD_SIZE_FELT] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [Felt; WORD_SIZE_FELT] {
    fn from(value: Word) -> Self {
        value.0
    }
}

impl From<&Word> for [u8; WORD_SIZE_BYTES] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [u8; WORD_SIZE_BYTES] {
    fn from(value: Word) -> Self {
        value.as_bytes()
    }
}

impl From<&Word> for String {
    /// The returned string starts with `0x`.
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for String {
    /// The returned string starts with `0x`.
    fn from(value: Word) -> Self {
        value.to_hex()
    }
}

// CONVERSIONS: TO WORD
// ================================================================================================

impl From<&[bool; WORD_SIZE_FELT]> for Word {
    fn from(value: &[bool; WORD_SIZE_FELT]) -> Self {
        (*value).into()
    }
}

impl From<[bool; WORD_SIZE_FELT]> for Word {
    fn from(value: [bool; WORD_SIZE_FELT]) -> Self {
        [value[0] as u32, value[1] as u32, value[2] as u32, value[3] as u32].into()
    }
}

impl From<&[u8; WORD_SIZE_FELT]> for Word {
    fn from(value: &[u8; WORD_SIZE_FELT]) -> Self {
        (*value).into()
    }
}

impl From<[u8; WORD_SIZE_FELT]> for Word {
    fn from(value: [u8; WORD_SIZE_FELT]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl From<&[u16; WORD_SIZE_FELT]> for Word {
    fn from(value: &[u16; WORD_SIZE_FELT]) -> Self {
        (*value).into()
    }
}

impl From<[u16; WORD_SIZE_FELT]> for Word {
    fn from(value: [u16; WORD_SIZE_FELT]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl From<&[u32; WORD_SIZE_FELT]> for Word {
    fn from(value: &[u32; WORD_SIZE_FELT]) -> Self {
        (*value).into()
    }
}

impl From<[u32; WORD_SIZE_FELT]> for Word {
    fn from(value: [u32; WORD_SIZE_FELT]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl TryFrom<&[u64; WORD_SIZE_FELT]> for Word {
    type Error = WordError;

    fn try_from(value: &[u64; WORD_SIZE_FELT]) -> Result<Self, WordError> {
        (*value).try_into()
    }
}

impl TryFrom<[u64; WORD_SIZE_FELT]> for Word {
    type Error = WordError;

    fn try_from(value: [u64; WORD_SIZE_FELT]) -> Result<Self, WordError> {
        Ok(Self([
            value[0].try_into().map_err(WordError::InvalidFieldElement)?,
            value[1].try_into().map_err(WordError::InvalidFieldElement)?,
            value[2].try_into().map_err(WordError::InvalidFieldElement)?,
            value[3].try_into().map_err(WordError::InvalidFieldElement)?,
        ]))
    }
}

impl From<&[Felt; WORD_SIZE_FELT]> for Word {
    fn from(value: &[Felt; WORD_SIZE_FELT]) -> Self {
        Self(*value)
    }
}

impl From<[Felt; WORD_SIZE_FELT]> for Word {
    fn from(value: [Felt; WORD_SIZE_FELT]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8; WORD_SIZE_BYTES]> for Word {
    type Error = WordError;

    fn try_from(value: &[u8; WORD_SIZE_BYTES]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<[u8; WORD_SIZE_BYTES]> for Word {
    type Error = WordError;

    fn try_from(value: [u8; WORD_SIZE_BYTES]) -> Result<Self, Self::Error> {
        // Note: the input length is known, the conversion from slice to array must succeed so the
        // `unwrap`s below are safe
        let a = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let c = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let d = u64::from_le_bytes(value[24..32].try_into().unwrap());

        if [a, b, c, d].iter().any(|v| *v >= Felt::MODULUS) {
            return Err(WordError::OutOfRange);
        }

        Ok(Word([Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)]))
    }
}

impl TryFrom<&[u8]> for Word {
    type Error = WordError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<&str> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes::<WORD_SIZE_BYTES>(value)
            .map_err(WordError::HexParse)
            .and_then(Word::try_from)
    }
}

impl TryFrom<String> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&String> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for Word {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for Word {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut inner: [Felt; WORD_SIZE_FELT] = [ZERO; WORD_SIZE_FELT];
        for inner in inner.iter_mut() {
            let e = source.read_u64()?;
            if e >= Felt::MODULUS {
                return Err(DeserializationError::InvalidValue(String::from(
                    "Value not in the appropriate range",
                )));
            }
            *inner = Felt::new(e);
        }

        Ok(Self(inner))
    }
}

// ITERATORS
// ================================================================================================
impl IntoIterator for Word {
    type Item = Felt;
    type IntoIter = <[Felt; 4] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use rand_utils::rand_value;

    use super::{Deserializable, Felt, Serializable, WORD_SIZE_BYTES, WORD_SIZE_FELT, Word};
    use crate::utils::SliceReader;

    #[test]
    fn word_serialization() {
        let e1 = Felt::new(rand_value());
        let e2 = Felt::new(rand_value());
        let e3 = Felt::new(rand_value());
        let e4 = Felt::new(rand_value());

        let d1 = Word([e1, e2, e3, e4]);

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(WORD_SIZE_BYTES, bytes.len());
        assert_eq!(bytes.len(), d1.get_size_hint());

        let mut reader = SliceReader::new(&bytes);
        let d2 = Word::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }

    #[test]
    fn word_encoding() {
        let word = Word([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        let string: String = word.into();
        let round_trip: Word = string.try_into().expect("decoding failed");

        assert_eq!(word, round_trip);
    }

    #[test]
    fn test_conversions() {
        let word = Word([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        // BY VALUE
        // ----------------------------------------------------------------------------------------
        let v: [bool; WORD_SIZE_FELT] = [true, false, true, true];
        let v2: Word = v.into();
        assert_eq!(v, <[bool; WORD_SIZE_FELT]>::try_from(v2).unwrap());

        let v: [u8; WORD_SIZE_FELT] = [0_u8, 1_u8, 2_u8, 3_u8];
        let v2: Word = v.into();
        assert_eq!(v, <[u8; WORD_SIZE_FELT]>::try_from(v2).unwrap());

        let v: [u16; WORD_SIZE_FELT] = [0_u16, 1_u16, 2_u16, 3_u16];
        let v2: Word = v.into();
        assert_eq!(v, <[u16; WORD_SIZE_FELT]>::try_from(v2).unwrap());

        let v: [u32; WORD_SIZE_FELT] = [0_u32, 1_u32, 2_u32, 3_u32];
        let v2: Word = v.into();
        assert_eq!(v, <[u32; WORD_SIZE_FELT]>::try_from(v2).unwrap());

        let v: [u64; WORD_SIZE_FELT] = word.into();
        let v2: Word = v.try_into().unwrap();
        assert_eq!(word, v2);

        let v: [Felt; WORD_SIZE_FELT] = word.into();
        let v2: Word = v.into();
        assert_eq!(word, v2);

        let v: [u8; WORD_SIZE_BYTES] = word.into();
        let v2: Word = v.try_into().unwrap();
        assert_eq!(word, v2);

        let v: String = word.into();
        let v2: Word = v.try_into().unwrap();
        assert_eq!(word, v2);

        // BY REF
        // ----------------------------------------------------------------------------------------
        let v: [bool; WORD_SIZE_FELT] = [true, false, true, true];
        let v2: Word = (&v).into();
        assert_eq!(v, <[bool; WORD_SIZE_FELT]>::try_from(&v2).unwrap());

        let v: [u8; WORD_SIZE_FELT] = [0_u8, 1_u8, 2_u8, 3_u8];
        let v2: Word = (&v).into();
        assert_eq!(v, <[u8; WORD_SIZE_FELT]>::try_from(&v2).unwrap());

        let v: [u16; WORD_SIZE_FELT] = [0_u16, 1_u16, 2_u16, 3_u16];
        let v2: Word = (&v).into();
        assert_eq!(v, <[u16; WORD_SIZE_FELT]>::try_from(&v2).unwrap());

        let v: [u32; WORD_SIZE_FELT] = [0_u32, 1_u32, 2_u32, 3_u32];
        let v2: Word = (&v).into();
        assert_eq!(v, <[u32; WORD_SIZE_FELT]>::try_from(&v2).unwrap());

        let v: [u64; WORD_SIZE_FELT] = (&word).into();
        let v2: Word = (&v).try_into().unwrap();
        assert_eq!(word, v2);

        let v: [Felt; WORD_SIZE_FELT] = (&word).into();
        let v2: Word = (&v).into();
        assert_eq!(word, v2);

        let v: [u8; WORD_SIZE_BYTES] = (&word).into();
        let v2: Word = (&v).try_into().unwrap();
        assert_eq!(word, v2);

        let v: String = (&word).into();
        let v2: Word = (&v).try_into().unwrap();
        assert_eq!(word, v2);
    }
}
