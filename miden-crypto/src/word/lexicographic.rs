use core::cmp::Ordering;

use super::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{Felt, WORD_SIZE, Word};

// LEXICOGRAPHIC WORD
// ================================================================================================

/// A [`Word`] wrapper with lexicographic ordering.
///
/// This is a wrapper around any [`Word`] convertible type that overrides the equality and ordering
/// implementations with a lexigographic one based on the wrapped type's [`Word`] representation.
#[derive(Debug, Clone, Copy)]
pub struct LexicographicWord<T: Into<Word> = Word>(T);

impl<T: Into<Word>> LexicographicWord<T> {
    /// Wraps the provided value into a new [`LexicographicWord`].
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Returns a reference to the inner value.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Consumes self and returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl From<[Felt; WORD_SIZE]> for LexicographicWord {
    fn from(value: [Felt; WORD_SIZE]) -> Self {
        Self(value.into())
    }
}

impl From<Word> for LexicographicWord {
    fn from(word: Word) -> Self {
        Self(word)
    }
}

impl<T: Into<Word>> From<LexicographicWord<T>> for Word {
    fn from(key: LexicographicWord<T>) -> Self {
        key.0.into()
    }
}

impl<T: Into<Word> + Copy> PartialEq for LexicographicWord<T> {
    fn eq(&self, other: &Self) -> bool {
        let self_word: Word = self.0.into();
        let other_word: Word = other.0.into();
        self_word == other_word
    }
}

impl<T: Into<Word> + Copy> Eq for LexicographicWord<T> {}

impl<T: Into<Word> + Copy> PartialOrd for LexicographicWord<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Into<Word> + Copy> Ord for LexicographicWord<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_word: Word = self.0.into();
        let other_word: Word = other.0.into();

        for (felt0, felt1) in self_word
            .iter()
            .rev()
            .map(Felt::as_int)
            .zip(other_word.iter().rev().map(Felt::as_int))
        {
            let ordering = felt0.cmp(&felt1);
            if let Ordering::Less | Ordering::Greater = ordering {
                return ordering;
            }
        }

        Ordering::Equal
    }
}

// SERIALIZATION
// ================================================================================================

impl<T: Into<Word> + Copy> Serializable for LexicographicWord<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.into().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.into().get_size_hint()
    }
}

impl<T: Into<Word> + From<Word>> Deserializable for LexicographicWord<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word = Word::read_from(source)?;

        Ok(Self::new(T::from(word)))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct NoteId(Word);

    impl From<Word> for NoteId {
        fn from(value: Word) -> Self {
            Self(value)
        }
    }

    impl From<NoteId> for Word {
        fn from(value: NoteId) -> Self {
            value.0
        }
    }

    #[test]
    fn lexicographic_word_ordering() {
        for (expected, key0, key1) in [
            (Ordering::Equal, [0, 0, 0, 0u32], [0, 0, 0, 0u32]),
            (Ordering::Greater, [1, 0, 0, 0u32], [0, 0, 0, 0u32]),
            (Ordering::Greater, [0, 1, 0, 0u32], [0, 0, 0, 0u32]),
            (Ordering::Greater, [0, 0, 1, 0u32], [0, 0, 0, 0u32]),
            (Ordering::Greater, [0, 0, 0, 1u32], [0, 0, 0, 0u32]),
            (Ordering::Less, [0, 0, 0, 0u32], [1, 0, 0, 0u32]),
            (Ordering::Less, [0, 0, 0, 0u32], [0, 1, 0, 0u32]),
            (Ordering::Less, [0, 0, 0, 0u32], [0, 0, 1, 0u32]),
            (Ordering::Less, [0, 0, 0, 0u32], [0, 0, 0, 1u32]),
            (Ordering::Greater, [0, 0, 0, 1u32], [1, 1, 1, 0u32]),
            (Ordering::Greater, [0, 0, 1, 0u32], [1, 1, 0, 0u32]),
            (Ordering::Less, [1, 1, 1, 0u32], [0, 0, 0, 1u32]),
            (Ordering::Less, [1, 1, 0, 0u32], [0, 0, 1, 0u32]),
        ] {
            assert_eq!(
                LexicographicWord::from(key0.map(Felt::from))
                    .cmp(&LexicographicWord::from(key1.map(Felt::from))),
                expected
            );
        }
    }

    #[test]
    fn lexicographic_serialization() {
        let word = Word::from([1u64, 2, 3, 4].map(Felt::new));
        let key = LexicographicWord::new(word);
        let bytes = key.to_bytes();
        let deserialized_key = LexicographicWord::<Word>::read_from_bytes(&bytes).unwrap();
        assert_eq!(key, deserialized_key);

        let note_id = NoteId::from(word);
        let key = LexicographicWord::new(note_id);
        let bytes = key.to_bytes();
        let deserialized_key = LexicographicWord::<NoteId>::read_from_bytes(&bytes).unwrap();
        assert_eq!(key, deserialized_key);
    }
}
