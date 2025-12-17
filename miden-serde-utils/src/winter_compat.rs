//! Compatibility layer implementing miden-serde-utils traits for winter ecosystem types.

use crate::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// WINTER_MATH FIELD ELEMENT IMPLEMENTATIONS
// ================================================================================================

impl Serializable for winter_math::fields::f64::BaseElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.as_int());
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Deserializable for winter_math::fields::f64::BaseElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use winter_math::StarkField;
        let value = source.read_u64()?;
        if value >= Self::MODULUS {
            return Err(DeserializationError::InvalidValue(
                "field element value exceeds modulus".into(),
            ));
        }
        Ok(Self::new(value))
    }
}
