#![cfg(feature = "std")]
use alloc::string::String;

use p3_field::PrimeCharacteristicRing;

use super::{Deserializable, Felt, Serializable, WORD_SIZE_BYTES, WORD_SIZE_FELT, Word};
use crate::{rand::test_utils::rand_value, utils::SliceReader, word};

// TESTS
// ================================================================================================

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

#[test]
fn test_index() {
    let word = Word::new([
        Felt::from_u32(1_u32),
        Felt::from_u32(2_u32),
        Felt::from_u32(3_u32),
        Felt::from_u32(4_u32),
    ]);
    assert_eq!(word[0], Felt::from_u32(1_u32));
    assert_eq!(word[1], Felt::from_u32(2_u32));
    assert_eq!(word[2], Felt::from_u32(3_u32));
    assert_eq!(word[3], Felt::from_u32(4_u32));
}

#[test]
fn test_index_mut() {
    let mut word = Word::new([
        Felt::from_u32(1_u32),
        Felt::from_u32(2_u32),
        Felt::from_u32(3_u32),
        Felt::from_u32(4_u32),
    ]);

    word[0] = Felt::from_u32(5_u32);
    word[1] = Felt::from_u32(6_u32);
    word[2] = Felt::from_u32(7_u32);
    word[3] = Felt::from_u32(8_u32);
    assert_eq!(word[0], Felt::from_u32(5_u32));
    assert_eq!(word[1], Felt::from_u32(6_u32));
    assert_eq!(word[2], Felt::from_u32(7_u32));
    assert_eq!(word[3], Felt::from_u32(8_u32));
}

#[test]
fn test_index_mut_range() {
    let mut word = Word::new([
        Felt::from_u32(1_u32),
        Felt::from_u32(2_u32),
        Felt::from_u32(3_u32),
        Felt::from_u32(4_u32),
    ]);

    word[1..3].copy_from_slice(&[Felt::from_u32(6_u32), Felt::from_u32(7_u32)]);
    assert_eq!(word[1], Felt::from_u32(6_u32));
    assert_eq!(word[2], Felt::from_u32(7_u32));
}

#[rstest::rstest]
#[case::missing_prefix("1234")]
#[case::invalid_character("1234567890abcdefg")]
#[case::too_long("0xx00000000000000000000000000000000000000000000000000000000000000001")]
#[case::overflow_felt0("0x01000000ffffffff000000000000000000000000000000000000000000000000")]
#[case::overflow_felt1("0x000000000000000001000000ffffffff00000000000000000000000000000000")]
#[case::overflow_felt2("0x0000000000000000000000000000000001000000ffffffff0000000000000000")]
#[case::overflow_felt3("0x00000000000000000000000000000000000000000000000001000000ffffffff")]
#[should_panic]
fn word_macro_invalid(#[case] bad_input: &str) {
    word!(bad_input);
}

#[rstest::rstest]
#[case::each_digit("0x1234567890abcdef")]
#[case::empty("0x")]
#[case::zero("0x0")]
#[case::zero_full("0x0000000000000000000000000000000000000000000000000000000000000000")]
#[case::one_lsb("0x1")]
#[case::one_msb("0x0000000000000000000000000000000000000000000000000000000000000001")]
#[case::one_partial("0x0001")]
#[case::odd("0x123")]
#[case::even("0x1234")]
#[case::touch_each_felt("0x00000000000123450000000000067890000000000000abcd00000000000000ef")]
#[case::unique_felt("0x111111111111111155555555555555559999999999999999cccccccccccccccc")]
#[case::digits_on_repeat("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")]
fn word_macro(#[case] input: &str) {
    let uut = word!(input);

    // Right pad to 64 hex digits (66 including prefix). This is required by the
    // Word::try_from(String) implementation.
    let padded_input = format!("{input:<66}").replace(" ", "0");
    let expected = crate::Word::try_from(padded_input.as_str()).unwrap();

    assert_eq!(uut, expected);
}

#[rstest::rstest]
#[case::first_nibble("0x1000000000000000000000000000000000000000000000000000000000000000", crate::Word::new([Felt::new(16), Felt::new(0), Felt::new(0), Felt::new(0)]))]
#[case::second_nibble("0x0100000000000000000000000000000000000000000000000000000000000000", crate::Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]))]
#[case::all_first_nibbles("0x1000000000000000100000000000000010000000000000001000000000000000", crate::Word::new([Felt::new(16), Felt::new(16), Felt::new(16), Felt::new(16)]))]
#[case::all_first_nibbles_asc("0x1000000000000000200000000000000030000000000000004000000000000000", crate::Word::new([Felt::new(16), Felt::new(32), Felt::new(48), Felt::new(64)]))]
fn word_macro_endianness(#[case] input: &str, #[case] expected: crate::Word) {
    let uut = word!(input);
    assert_eq!(uut, expected);
}

#[test]
fn word_ord_respects_partialeq() {
    use core::cmp::Ordering;

    // Test that Word::cmp() respects the PartialEq invariant:
    // if a == b, then a.cmp(b) must equal Ordering::Equal

    let test_cases = vec![
        Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]),
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
        Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
        Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]),
    ];

    for word in test_cases {
        let word_copy = word;

        assert_eq!(word, word_copy, "Word should be equal to itself");
        assert_eq!(
            word.cmp(&word_copy),
            Ordering::Equal,
            "Word::cmp() should return Ordering::Equal for equal words: {:?}",
            word
        );
    }
}

#[test]
fn word_ord_btreemap_usage() {
    use alloc::collections::BTreeMap;

    // Test that Word works correctly as a BTreeMap key
    // This will fail if Ord and PartialEq are inconsistent

    let mut map = BTreeMap::new();
    let key1 = Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]);
    let key2 = Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]);

    map.insert(key1, "value1");

    // key2 should be equal to key1
    assert_eq!(key1, key2);

    // So map should contain key2
    assert!(map.contains_key(&key2), "BTreeMap should find key2 since it's equal to key1");

    // And getting by key2 should return the same value
    assert_eq!(map.get(&key2), Some(&"value1"));

    // Inserting with key2 should update the existing entry
    map.insert(key2, "value2");
    assert_eq!(map.len(), 1, "Map should still have only one entry");
    assert_eq!(map.get(&key1), Some(&"value2"));
}

#[test]
fn word_ord_consistency_with_partialeq() {
    use core::cmp::Ordering;

    // Comprehensive test that Ord is consistent with PartialEq
    // This is required by Rust's trait contract: if a == b, then a.cmp(b) == Ordering::Equal

    let test_pairs = vec![
        // Same values
        (
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
            Ordering::Equal,
        ),
        // Different first element
        (
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
            Word::new([Felt::new(2), Felt::new(2), Felt::new(3), Felt::new(4)]),
            Ordering::Less,
        ),
        // Different last element
        (
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(3)]),
            Ordering::Greater,
        ),
    ];

    for (w1, w2, expected_ordering) in test_pairs {
        let actual_ordering = w1.cmp(&w2);
        assert_eq!(
            actual_ordering, expected_ordering,
            "Word::cmp mismatch: {:?}.cmp({:?}) returned {:?}, expected {:?}",
            w1, w2, actual_ordering, expected_ordering
        );

        // Verify consistency with PartialEq
        match expected_ordering {
            Ordering::Equal => {
                assert_eq!(w1, w2, "Words should be equal when cmp returns Equal");
            },
            Ordering::Less => {
                assert_ne!(w1, w2, "Words should not be equal when cmp returns Less");
            },
            Ordering::Greater => {
                assert_ne!(w1, w2, "Words should not be equal when cmp returns Greater");
            },
        }
    }
}
