use core::fmt;
use core::ptr::NonNull;

use super::Nibble;

#[inline]
const fn mask_bit(n: usize) -> u32 {
    debug_assert!(n < 32);
    1 << (31 - n)
}

const MASKS: [u32; 16] = [
    mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(7) | mask_bit(16), // match 0000
    mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(7) | mask_bit(17), // match 0001
    mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(8) | mask_bit(18), // match 0010
    mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(8) | mask_bit(19), // match 0011
    mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(9) | mask_bit(20), // match 0100
    mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(9) | mask_bit(21), // match 0101
    mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(10) | mask_bit(22), // match 0110
    mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(10) | mask_bit(23), // match 0111
    mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(11) | mask_bit(24), // match 1000
    mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(11) | mask_bit(25), // match 1001
    mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(12) | mask_bit(26), // match 1010
    mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(12) | mask_bit(27), // match 1011
    mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(13) | mask_bit(28), // match 1100
    mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(13) | mask_bit(29), // match 1101
    mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(14) | mask_bit(30), // match 1110
    mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(14) | mask_bit(31), // match 1111
];

const CHILD_MASKS: [u32; 16] = [
    mask_bit(16), // 0000
    mask_bit(17), // 0001
    mask_bit(18), // 0010
    mask_bit(19), // 0011
    mask_bit(20), // 0100
    mask_bit(21), // 0101
    mask_bit(22), // 0110
    mask_bit(23), // 0111
    mask_bit(24), // 1000
    mask_bit(25), // 1001
    mask_bit(26), // 1010
    mask_bit(27), // 1011
    mask_bit(28), // 1100
    mask_bit(29), // 1101
    mask_bit(30), // 1110
    mask_bit(31), // 1111
];

#[rustfmt::skip]
const VALUE_MASKS: [[u32; 16]; 5] = [
    [
        // *
        mask_bit(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        // 0 == 0b0000 match 0*
        mask_bit(0) | mask_bit(1), 0, 0, 0, 0, 0, 0, 0,
        // 8 == 0b1000 match 1*
        mask_bit(0) | mask_bit(2), 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        // 0 == 0b0000 match 00*
        mask_bit(0) | mask_bit(1) | mask_bit(3), 0, 0, 0,
        // 4 == 0b0100 match 01*
        mask_bit(0) | mask_bit(1) | mask_bit(4), 0, 0, 0,
        // 8 == 0b1000 match 10*
        mask_bit(0) | mask_bit(2) | mask_bit(5), 0, 0, 0,
        // 12 == 0b1100 match 11*
        mask_bit(0) | mask_bit(2) | mask_bit(6), 0, 0, 0,
    ],
    [
        mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(7), 0,
        mask_bit(0) | mask_bit(1) | mask_bit(3) | mask_bit(8), 0,
        mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(9), 0,
        mask_bit(0) | mask_bit(1) | mask_bit(4) | mask_bit(10), 0,
        mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(11), 0,
        mask_bit(0) | mask_bit(2) | mask_bit(5) | mask_bit(12), 0,
        mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(13), 0,
        mask_bit(0) | mask_bit(2) | mask_bit(6) | mask_bit(14), 0,
    ],
    MASKS,
];

#[inline]
const fn exact_value_mask(nibble: u8, bits: u8) -> u32 {
    debug_assert!(nibble < 16);
    debug_assert!(bits < 5);
    let offset = ((nibble << bits) & 0b1111_0000) >> bits;
    let v = VALUE_MASKS[bits as usize][offset as usize];
    1u32 << v.trailing_zeros()
}

#[inline]
const fn match_value_mask(nibble: u8, bits: u8) -> u32 {
    debug_assert!(nibble < 16);
    debug_assert!(bits < 5);
    let offset = ((nibble << bits) & 0b1111_0000) >> bits;
    VALUE_MASKS[bits as usize][offset as usize]
}

pub(super) struct Node<V> {
    bitmap: u32,
    values: [Option<Box<V>>; 32],
    children: [Option<NonNull<Node<V>>>; 16],
}

impl<V> Node<V> {
    const END_NODE_BIT: u32 = 1 << 16;

    #[inline]
    fn empty() -> Self {
        Self {
            bitmap: 0,
            values: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            children: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
        }
    }

    /// Create a internal node
    #[inline]
    pub fn internal() -> NonNull<Self> {
        let boxed = Box::new(Self::empty());
        let ptr = Box::into_raw(boxed);
        NonNull::new(ptr).unwrap()
    }

    /// Create an end node
    #[inline]
    pub fn end() -> NonNull<Self> {
        let mut me = Self::empty();
        me.bitmap |= Self::END_NODE_BIT;
        let boxed = Box::new(me);
        let ptr = Box::into_raw(boxed);
        NonNull::new(ptr).unwrap()
    }

    #[inline]
    pub const fn is_end(&self) -> bool {
        self.bitmap & Self::END_NODE_BIT != 0
    }

    #[inline]
    const fn value_bits(&self) -> u32 {
        if self.is_end() {
            self.bitmap & !Self::END_NODE_BIT
        } else {
            self.bitmap & 0xffff_0000
        }
    }

    #[inline]
    const fn child_bits(&self) -> u32 {
        debug_assert!(!self.is_end());
        self.bitmap & 0x0000_ffff
    }

    #[inline]
    pub fn list_values(&self, nibble: Nibble) -> Vec<&V> {
        let mask = match_value_mask(nibble.byte, nibble.bits);
        let masked = self.value_bits() & mask;
        (0..32u32)
            .filter(|i| masked & (1 << (31 - i)) != 0)
            .map(|i| self.values[i as usize].as_ref().unwrap())
            .map(|p| p.as_ref())
            .collect()
    }

    #[inline]
    pub fn get_longest_match_value(&self, nibble: Nibble) -> Option<&V> {
        let mask = match_value_mask(nibble.byte, nibble.bits);
        let offset = (self.value_bits() & mask).trailing_zeros() as usize;
        if offset == 32 {
            return None;
        }

        let index = 31 - offset;
        self.values[index].as_ref().map(|p| p.as_ref())
    }

    #[inline]
    pub fn get_exact_match_value(&self, nibble: Nibble) -> Option<&V> {
        let mask = exact_value_mask(nibble.byte, nibble.bits);
        let offset = (self.value_bits() & mask).trailing_zeros() as usize;
        if offset == 32 {
            return None;
        }

        let index = 31 - offset;
        self.values[index].as_ref().map(|p| p.as_ref())
    }

    #[inline]
    pub fn set_value(&mut self, nibble: Nibble, value: V) {
        let mask = exact_value_mask(nibble.byte, nibble.bits);
        let offset = mask.trailing_zeros() as usize;
        debug_assert!(offset < 32, "offset = {}", offset);
        let index = 31 - offset;

        debug_assert!(self.values[index].is_none());
        self.bitmap |= 1 << offset;
        self.values[index] = Some(Box::new(value));
    }

    #[inline]
    pub fn remove_value(&mut self, nibble: Nibble) -> Option<V> {
        let mask = exact_value_mask(nibble.byte, nibble.bits);
        let offset = (self.value_bits() & mask).trailing_zeros() as usize;
        if offset == 32 {
            return None;
        }
        let index = 31 - offset;
        self.values[index].take().map(|p| *p)
    }

    #[inline]
    pub fn get_child(&self, nibble: u8) -> Option<NonNull<Node<V>>> {
        let mask = CHILD_MASKS[nibble as usize];
        let masked = self.child_bits() & mask;
        if masked.trailing_zeros() > 15 {
            return None;
        }
        let index = 15 - masked.trailing_zeros();
        self.children[index as usize]
    }

    #[inline]
    pub fn set_child(&mut self, nibble: u8, node: NonNull<Node<V>>) {
        debug_assert!(nibble < 16);

        let i = nibble as usize;
        debug_assert!(self.children[i].is_none());
        debug_assert!(self.bitmap & CHILD_MASKS[i] == 0);

        self.children[i] = Some(node);
        self.bitmap |= CHILD_MASKS[i];
    }
}

impl<V> fmt::Debug for Node<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Node");
        debug
            .field("is_end", &self.is_end())
            .field("values", &format_args!("{:032b}", self.value_bits()));
        if !self.is_end() {
            debug.field("children", &format_args!("{:016b}", self.child_bits()));
        }

        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask() {
        pub const MSB: u32 = 1 << 31;

        pub static MATCH_MASKS: [u32; 16] = [
            MSB | MSB >> 1 | MSB >> 3 | MSB >> 7 | MSB >> 16, // 0000
            MSB | MSB >> 1 | MSB >> 3 | MSB >> 7 | MSB >> 17, // 0001
            MSB | MSB >> 1 | MSB >> 3 | MSB >> 8 | MSB >> 18, // 0010
            MSB | MSB >> 1 | MSB >> 3 | MSB >> 8 | MSB >> 19, // 0011
            MSB | MSB >> 1 | MSB >> 4 | MSB >> 9 | MSB >> 20, // 0100
            MSB | MSB >> 1 | MSB >> 4 | MSB >> 9 | MSB >> 21, // 0101
            MSB | MSB >> 1 | MSB >> 4 | MSB >> 10 | MSB >> 22, // 0110
            MSB | MSB >> 1 | MSB >> 4 | MSB >> 10 | MSB >> 23, // 0111
            MSB | MSB >> 2 | MSB >> 5 | MSB >> 11 | MSB >> 24, // 1000
            MSB | MSB >> 2 | MSB >> 5 | MSB >> 11 | MSB >> 25, // 1001
            MSB | MSB >> 2 | MSB >> 5 | MSB >> 12 | MSB >> 26, // 1010
            MSB | MSB >> 2 | MSB >> 5 | MSB >> 12 | MSB >> 27, // 1011
            MSB | MSB >> 2 | MSB >> 6 | MSB >> 13 | MSB >> 28, // 1100
            MSB | MSB >> 2 | MSB >> 6 | MSB >> 13 | MSB >> 29, // 1101
            MSB | MSB >> 2 | MSB >> 6 | MSB >> 14 | MSB >> 30, // 1110
            MSB | MSB >> 2 | MSB >> 6 | MSB >> 14 | MSB >> 31, /* 1111 */
        ];

        for i in 0..16 {
            assert_eq!(MATCH_MASKS[i], MASKS[i]);
        }
    }

    #[test]
    fn test_node() {
        let mut root = Node::<u64>::internal();
        let p = unsafe { root.as_mut() };
        p.set_child(0b0010, Node::end());
        assert!(p.get_child(0b0010).is_some());
    }

    #[test]
    fn test_exact_value_mask() {
        let tests = [
            ((0b0000, 0), [0b1000_0000, 0, 0, 0]),
            ((0b0000, 1), [0b0100_0000, 0, 0, 0]),
            ((0b1000, 1), [0b0010_0000, 0, 0, 0]),
            ((0b0000, 2), [0b0001_0000, 0, 0, 0]),
            ((0b0100, 2), [0b0000_1000, 0, 0, 0]),
        ];

        for (input, expected) in tests.into_iter() {
            let (nibble, bits) = input;
            let mask = exact_value_mask(nibble, bits);
            let actual = mask.to_be_bytes();
            assert_eq!(
                actual,
                expected,
                "input: ({nibble:08b}, {bits}) = {mask:032b}, expected: {:032b}",
                u32::from_be_bytes(expected),
            );
        }
    }

    #[test]
    fn test_match_value_mask() {
        let tests = [
            ((0b0000, 0), [0b1000_0000, 0, 0, 0]),
            ((0b0000, 1), [0b1100_0000, 0, 0, 0]),
            ((0b1000, 1), [0b1010_0000, 0, 0, 0]),
            ((0b0000, 2), [0b1101_0000, 0, 0, 0]),
            ((0b0100, 2), [0b1100_1000, 0, 0, 0]),
        ];

        for (input, expected) in tests.into_iter() {
            let (nibble, bits) = input;
            let mask = match_value_mask(nibble, bits);
            let actual = mask.to_be_bytes();
            assert_eq!(
                actual,
                expected,
                "input: ({nibble:08b}, {bits}) = {mask:032b}, expected: {:032b}",
                u32::from_be_bytes(expected),
            );
        }
    }
}
