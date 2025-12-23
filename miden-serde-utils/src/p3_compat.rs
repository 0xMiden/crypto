//! Compatibility layer implementing miden-serde-utils traits for Plonky3 types.

use alloc::format;

use p3_field::PrimeField64;

use crate::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// P3_MIDEN_GOLDILOCKS FIELD ELEMENT IMPLEMENTATIONS
// ================================================================================================

impl Serializable for p3_goldilocks::Goldilocks {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.as_canonical_u64());
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Deserializable for p3_goldilocks::Goldilocks {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use p3_field::integers::QuotientMap;

        let value = source.read_u64()?;
        Self::from_canonical_checked(value).ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "value {} is not a valid Goldilocks field element",
                value
            ))
        })
    }
}
