use alloc::string::String;
use core::{
    cmp::Ordering,
    fmt::Display,
    hash::{Hash, Hasher},
    ops::Deref,
    slice,
};

use thiserror::Error;

use super::{DIGEST_BYTES, DIGEST_SIZE, Digest, Felt, StarkField, ZERO};
use crate::{
    rand::Randomizable,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, HexParseError, Serializable,
        bytes_to_hex_string, hex_to_bytes,
    },
};

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

/// An RPO digest consisting of 4 field elements.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
pub struct RpoDigest([Felt; DIGEST_SIZE]);

impl RpoDigest {
    /// The serialized size of the digest in bytes.
    pub const SERIALIZED_SIZE: usize = DIGEST_BYTES;

    /// Creates a new RpoDigest from the given field elements.
    pub const fn new(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    /// Returns the digest as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        self.as_ref()
    }

    /// Returns the digest as a byte array.
    pub fn as_bytes(&self) -> [u8; DIGEST_BYTES] {
        <Self as Digest>::as_bytes(self)
    }

    /// Returns an iterator over the elements of multiple digests.
    pub fn digests_as_elements_iter<'a, I>(digests: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        digests.flat_map(|d| d.0.iter())
    }

    /// Returns all elements of multiple digests as a slice.
    pub fn digests_as_elements(digests: &[Self]) -> &[Felt] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_SIZE;
        unsafe { slice::from_raw_parts(p as *const Felt, len) }
    }

    /// Returns hexadecimal representation of this digest prefixed with `0x`.
    pub fn to_hex(&self) -> String {
        bytes_to_hex_string(self.as_bytes())
    }
}

impl Hash for RpoDigest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl Digest for RpoDigest {
    fn as_bytes(&self) -> [u8; DIGEST_BYTES] {
        let mut result = [0; DIGEST_BYTES];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }
}

impl Deref for RpoDigest {
    type Target = [Felt; DIGEST_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for RpoDigest {
    fn cmp(&self, other: &Self) -> Ordering {
        // compare the inner u64 of both elements.
        //
        // it will iterate the elements and will return the first computation different than
        // `Equal`. Otherwise, the ordering is equal.
        //
        // the endianness is irrelevant here because since, this being a cryptographically secure
        // hash computation, the digest shouldn't have any ordered property of its input.
        //
        // finally, we use `Felt::inner` instead of `Felt::as_int` so we avoid performing a
        // montgomery reduction for every limb. that is safe because every inner element of the
        // digest is guaranteed to be in its canonical form (that is, `x in [0,p)`).
        self.0.iter().map(Felt::inner).zip(other.0.iter().map(Felt::inner)).fold(
            Ordering::Equal,
            |ord, (a, b)| match ord {
                Ordering::Equal => a.cmp(&b),
                _ => ord,
            },
        )
    }
}

impl PartialOrd for RpoDigest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for RpoDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let encoded: String = self.into();
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl Randomizable for RpoDigest {
    const VALUE_SIZE: usize = DIGEST_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: Option<[u8; 32]> = bytes.try_into().ok();
        if let Some(bytes_array) = bytes_array {
            Self::try_from(bytes_array).ok()
        } else {
            None
        }
    }
}

// CONVERSIONS: FROM RPO DIGEST
// ================================================================================================

/// Errors that can occur when working with RpoDigest.
#[derive(Debug, Error)]
pub enum RpoDigestError {
    /// Failed to convert digest field element to the specified type.
    #[error("failed to convert digest field element to {0}")]
    TypeConversion(&'static str),
    /// Field element conversion failed due to invalid value.
    #[error("failed to convert to field element: {0}")]
    InvalidFieldElement(String),
}

impl TryFrom<&RpoDigest> for [bool; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: &RpoDigest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<RpoDigest> for [bool; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: RpoDigest) -> Result<Self, Self::Error> {
        fn to_bool(v: u64) -> Option<bool> {
            if v <= 1 { Some(v == 1) } else { None }
        }

        Ok([
            to_bool(value.0[0].as_int()).ok_or(RpoDigestError::TypeConversion("bool"))?,
            to_bool(value.0[1].as_int()).ok_or(RpoDigestError::TypeConversion("bool"))?,
            to_bool(value.0[2].as_int()).ok_or(RpoDigestError::TypeConversion("bool"))?,
            to_bool(value.0[3].as_int()).ok_or(RpoDigestError::TypeConversion("bool"))?,
        ])
    }
}

impl TryFrom<&RpoDigest> for [u8; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: &RpoDigest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<RpoDigest> for [u8; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: RpoDigest) -> Result<Self, Self::Error> {
        Ok([
            value.0[0]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u8"))?,
            value.0[1]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u8"))?,
            value.0[2]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u8"))?,
            value.0[3]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u8"))?,
        ])
    }
}

impl TryFrom<&RpoDigest> for [u16; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: &RpoDigest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<RpoDigest> for [u16; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: RpoDigest) -> Result<Self, Self::Error> {
        Ok([
            value.0[0]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u16"))?,
            value.0[1]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u16"))?,
            value.0[2]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u16"))?,
            value.0[3]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u16"))?,
        ])
    }
}

impl TryFrom<&RpoDigest> for [u32; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: &RpoDigest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<RpoDigest> for [u32; DIGEST_SIZE] {
    type Error = RpoDigestError;

    fn try_from(value: RpoDigest) -> Result<Self, Self::Error> {
        Ok([
            value.0[0]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u32"))?,
            value.0[1]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u32"))?,
            value.0[2]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u32"))?,
            value.0[3]
                .as_int()
                .try_into()
                .map_err(|_| RpoDigestError::TypeConversion("u32"))?,
        ])
    }
}

impl From<&RpoDigest> for [u64; DIGEST_SIZE] {
    fn from(value: &RpoDigest) -> Self {
        (*value).into()
    }
}

impl From<RpoDigest> for [u64; DIGEST_SIZE] {
    fn from(value: RpoDigest) -> Self {
        [
            value.0[0].as_int(),
            value.0[1].as_int(),
            value.0[2].as_int(),
            value.0[3].as_int(),
        ]
    }
}

impl From<&RpoDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: &RpoDigest) -> Self {
        (*value).into()
    }
}

impl From<RpoDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: RpoDigest) -> Self {
        value.0
    }
}

impl From<&RpoDigest> for [u8; DIGEST_BYTES] {
    fn from(value: &RpoDigest) -> Self {
        (*value).into()
    }
}

impl From<RpoDigest> for [u8; DIGEST_BYTES] {
    fn from(value: RpoDigest) -> Self {
        value.as_bytes()
    }
}

impl From<&RpoDigest> for String {
    /// The returned string starts with `0x`.
    fn from(value: &RpoDigest) -> Self {
        (*value).into()
    }
}

impl From<RpoDigest> for String {
    /// The returned string starts with `0x`.
    fn from(value: RpoDigest) -> Self {
        value.to_hex()
    }
}

// CONVERSIONS: TO RPO DIGEST
// ================================================================================================

impl From<&[bool; DIGEST_SIZE]> for RpoDigest {
    fn from(value: &[bool; DIGEST_SIZE]) -> Self {
        (*value).into()
    }
}

impl From<[bool; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [bool; DIGEST_SIZE]) -> Self {
        [value[0] as u32, value[1] as u32, value[2] as u32, value[3] as u32].into()
    }
}

impl From<&[u8; DIGEST_SIZE]> for RpoDigest {
    fn from(value: &[u8; DIGEST_SIZE]) -> Self {
        (*value).into()
    }
}

impl From<[u8; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [u8; DIGEST_SIZE]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl From<&[u16; DIGEST_SIZE]> for RpoDigest {
    fn from(value: &[u16; DIGEST_SIZE]) -> Self {
        (*value).into()
    }
}

impl From<[u16; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [u16; DIGEST_SIZE]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl From<&[u32; DIGEST_SIZE]> for RpoDigest {
    fn from(value: &[u32; DIGEST_SIZE]) -> Self {
        (*value).into()
    }
}

impl From<[u32; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [u32; DIGEST_SIZE]) -> Self {
        Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()])
    }
}

impl TryFrom<&[u64; DIGEST_SIZE]> for RpoDigest {
    type Error = RpoDigestError;

    fn try_from(value: &[u64; DIGEST_SIZE]) -> Result<Self, RpoDigestError> {
        (*value).try_into()
    }
}

impl TryFrom<[u64; DIGEST_SIZE]> for RpoDigest {
    type Error = RpoDigestError;

    fn try_from(value: [u64; DIGEST_SIZE]) -> Result<Self, RpoDigestError> {
        Ok(Self([
            value[0].try_into().map_err(RpoDigestError::InvalidFieldElement)?,
            value[1].try_into().map_err(RpoDigestError::InvalidFieldElement)?,
            value[2].try_into().map_err(RpoDigestError::InvalidFieldElement)?,
            value[3].try_into().map_err(RpoDigestError::InvalidFieldElement)?,
        ]))
    }
}

impl From<&[Felt; DIGEST_SIZE]> for RpoDigest {
    fn from(value: &[Felt; DIGEST_SIZE]) -> Self {
        Self(*value)
    }
}

impl From<[Felt; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8; DIGEST_BYTES]> for RpoDigest {
    type Error = HexParseError;

    fn try_from(value: &[u8; DIGEST_BYTES]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<[u8; DIGEST_BYTES]> for RpoDigest {
    type Error = HexParseError;

    fn try_from(value: [u8; DIGEST_BYTES]) -> Result<Self, Self::Error> {
        // Note: the input length is known, the conversion from slice to array must succeed so the
        // `unwrap`s below are safe
        let a = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let c = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let d = u64::from_le_bytes(value[24..32].try_into().unwrap());

        if [a, b, c, d].iter().any(|v| *v >= Felt::MODULUS) {
            return Err(HexParseError::OutOfRange);
        }

        Ok(RpoDigest([Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)]))
    }
}

impl TryFrom<&[u8]> for RpoDigest {
    type Error = HexParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<&str> for RpoDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes::<DIGEST_BYTES>(value).and_then(RpoDigest::try_from)
    }
}

impl TryFrom<String> for RpoDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&String> for RpoDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for RpoDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for RpoDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut inner: [Felt; DIGEST_SIZE] = [ZERO; DIGEST_SIZE];
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
impl IntoIterator for RpoDigest {
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

    use super::{DIGEST_BYTES, DIGEST_SIZE, Deserializable, Felt, RpoDigest, Serializable};
    use crate::utils::SliceReader;

    #[test]
    fn digest_serialization() {
        let e1 = Felt::new(rand_value());
        let e2 = Felt::new(rand_value());
        let e3 = Felt::new(rand_value());
        let e4 = Felt::new(rand_value());

        let d1 = RpoDigest([e1, e2, e3, e4]);

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(DIGEST_BYTES, bytes.len());
        assert_eq!(bytes.len(), d1.get_size_hint());

        let mut reader = SliceReader::new(&bytes);
        let d2 = RpoDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_encoding() {
        let digest = RpoDigest([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        let string: String = digest.into();
        let round_trip: RpoDigest = string.try_into().expect("decoding failed");

        assert_eq!(digest, round_trip);
    }

    #[test]
    fn test_conversions() {
        let digest = RpoDigest([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        // BY VALUE
        // ----------------------------------------------------------------------------------------
        let v: [bool; DIGEST_SIZE] = [true, false, true, true];
        let v2: RpoDigest = v.into();
        assert_eq!(v, <[bool; DIGEST_SIZE]>::try_from(v2).unwrap());

        let v: [u8; DIGEST_SIZE] = [0_u8, 1_u8, 2_u8, 3_u8];
        let v2: RpoDigest = v.into();
        assert_eq!(v, <[u8; DIGEST_SIZE]>::try_from(v2).unwrap());

        let v: [u16; DIGEST_SIZE] = [0_u16, 1_u16, 2_u16, 3_u16];
        let v2: RpoDigest = v.into();
        assert_eq!(v, <[u16; DIGEST_SIZE]>::try_from(v2).unwrap());

        let v: [u32; DIGEST_SIZE] = [0_u32, 1_u32, 2_u32, 3_u32];
        let v2: RpoDigest = v.into();
        assert_eq!(v, <[u32; DIGEST_SIZE]>::try_from(v2).unwrap());

        let v: [u64; DIGEST_SIZE] = digest.into();
        let v2: RpoDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [Felt; DIGEST_SIZE] = digest.into();
        let v2: RpoDigest = v.into();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = digest.into();
        let v2: RpoDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: String = digest.into();
        let v2: RpoDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        // BY REF
        // ----------------------------------------------------------------------------------------
        let v: [bool; DIGEST_SIZE] = [true, false, true, true];
        let v2: RpoDigest = (&v).into();
        assert_eq!(v, <[bool; DIGEST_SIZE]>::try_from(&v2).unwrap());

        let v: [u8; DIGEST_SIZE] = [0_u8, 1_u8, 2_u8, 3_u8];
        let v2: RpoDigest = (&v).into();
        assert_eq!(v, <[u8; DIGEST_SIZE]>::try_from(&v2).unwrap());

        let v: [u16; DIGEST_SIZE] = [0_u16, 1_u16, 2_u16, 3_u16];
        let v2: RpoDigest = (&v).into();
        assert_eq!(v, <[u16; DIGEST_SIZE]>::try_from(&v2).unwrap());

        let v: [u32; DIGEST_SIZE] = [0_u32, 1_u32, 2_u32, 3_u32];
        let v2: RpoDigest = (&v).into();
        assert_eq!(v, <[u32; DIGEST_SIZE]>::try_from(&v2).unwrap());

        let v: [u64; DIGEST_SIZE] = (&digest).into();
        let v2: RpoDigest = (&v).try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [Felt; DIGEST_SIZE] = (&digest).into();
        let v2: RpoDigest = (&v).into();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = (&digest).into();
        let v2: RpoDigest = (&v).try_into().unwrap();
        assert_eq!(digest, v2);

        let v: String = (&digest).into();
        let v2: RpoDigest = (&v).try_into().unwrap();
        assert_eq!(digest, v2);
    }
}
