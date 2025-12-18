//! Implements miden-serde-utils serialization traits for winterfell types.
//!
//! Adapters bridge between miden_serde_utils and winter_utils trait systems to ensure
//! identical binary formats.

use winter_utils::{
    ByteReader as WinterByteReader, ByteWriter as WinterByteWriter,
    Deserializable as WinterDeserializable, Serializable as WinterSerializable,
};

use crate::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// ADAPTER TYPES
// ================================================================================================

/// Wraps a miden [ByteWriter] to implement winter_utils [ByteWriter].
struct WriterAdapter<'a, W: ByteWriter>(&'a mut W);

impl<'a, W: ByteWriter> WinterByteWriter for WriterAdapter<'a, W> {
    fn write_u8(&mut self, value: u8) {
        self.0.write_u8(value);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.0.write_bytes(bytes);
    }
}

/// Wraps a miden [ByteReader] to implement winter_utils [ByteReader].
struct ReaderAdapter<'a, R: ByteReader>(&'a mut R);

impl<'a, R: ByteReader> WinterByteReader for ReaderAdapter<'a, R> {
    fn read_u8(&mut self) -> Result<u8, winter_utils::DeserializationError> {
        self.0.read_u8().map_err(to_winter_error)
    }

    fn peek_u8(&self) -> Result<u8, winter_utils::DeserializationError> {
        self.0.peek_u8().map_err(to_winter_error)
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], winter_utils::DeserializationError> {
        self.0.read_slice(len).map_err(to_winter_error)
    }

    fn read_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], winter_utils::DeserializationError> {
        self.0.read_array().map_err(to_winter_error)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), winter_utils::DeserializationError> {
        self.0.check_eor(num_bytes).map_err(to_winter_error)
    }

    fn has_more_bytes(&self) -> bool {
        self.0.has_more_bytes()
    }
}

fn to_winter_error(err: DeserializationError) -> winter_utils::DeserializationError {
    match err {
        DeserializationError::UnexpectedEOF => winter_utils::DeserializationError::UnexpectedEOF,
        DeserializationError::InvalidValue(msg) => {
            winter_utils::DeserializationError::InvalidValue(msg)
        },
        DeserializationError::UnknownError(msg) => {
            winter_utils::DeserializationError::UnknownError(msg)
        },
    }
}

fn from_winter_error(err: winter_utils::DeserializationError) -> DeserializationError {
    match err {
        winter_utils::DeserializationError::UnexpectedEOF => DeserializationError::UnexpectedEOF,
        winter_utils::DeserializationError::InvalidValue(msg) => {
            DeserializationError::InvalidValue(msg)
        },
        winter_utils::DeserializationError::UnknownError(msg) => {
            DeserializationError::UnknownError(msg)
        },
        winter_utils::DeserializationError::UnconsumedBytes => {
            DeserializationError::InvalidValue("unconsumed bytes remaining".into())
        },
    }
}

// WINTER_MATH FIELD ELEMENT IMPLEMENTATIONS
// ================================================================================================
// Direct implementations without adapters.

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

// WINTER_AIR PROOF IMPLEMENTATIONS
// ================================================================================================
// Adapter-based implementations due to private fields and complex nested structures.

impl Serializable for winter_air::proof::Context {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut adapter = WriterAdapter(target);
        WinterSerializable::write_into(self, &mut adapter);
    }
}

impl Deserializable for winter_air::proof::Context {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut adapter = ReaderAdapter(source);
        WinterDeserializable::read_from(&mut adapter).map_err(from_winter_error)
    }
}

impl Serializable for winter_air::proof::Queries {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut adapter = WriterAdapter(target);
        WinterSerializable::write_into(self, &mut adapter);
    }

    fn get_size_hint(&self) -> usize {
        WinterSerializable::get_size_hint(self)
    }
}

impl Deserializable for winter_air::proof::Queries {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut adapter = ReaderAdapter(source);
        WinterDeserializable::read_from(&mut adapter).map_err(from_winter_error)
    }
}

impl Serializable for winter_air::proof::Proof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut adapter = WriterAdapter(target);
        WinterSerializable::write_into(self, &mut adapter);
    }
}

impl Deserializable for winter_air::proof::Proof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut adapter = ReaderAdapter(source);
        WinterDeserializable::read_from(&mut adapter).map_err(from_winter_error)
    }
}
