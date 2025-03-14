use super::forest::Forest;

/// Iterate over the bits of a `usize` and yields the bit positions for the true bits.
pub struct TrueBitPositionIterator {
    value: Forest,
}

impl TrueBitPositionIterator {
    pub fn new(value: Forest) -> TrueBitPositionIterator {
        TrueBitPositionIterator { value }
    }
}

impl Iterator for TrueBitPositionIterator {
    type Item = Forest;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        // trailing_zeros is computed with the intrinsic cttz. [Rust 1.67.0] x86 uses the `bsf`
        // instruction. AArch64 uses the `rbit clz` instructions.
        let mask = self.value.smallest_tree_checked();

        if mask.is_empty() {
            None
        } else {
            self.value ^= mask;
            Some(mask)
        }
    }
}

impl DoubleEndedIterator for TrueBitPositionIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        // trailing_zeros is computed with the intrinsic ctlz. [Rust 1.67.0] x86 uses the `bsr`
        // instruction. AArch64 uses the `clz` instruction.
        let zeros = self.value.0.leading_zeros();

        if zeros == usize::BITS {
            None
        } else {
            let bit_position = usize::BITS - zeros - 1;
            let mask = Forest(1 << bit_position);
            self.value ^= mask;
            Some(mask)
        }
    }
}
