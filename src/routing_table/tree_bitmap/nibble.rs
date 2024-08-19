use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::{Ipv4Cidr, Ipv6Cidr};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Nibble {
    pub byte: u8,
    pub bits: u8,
}

impl Nibble {
    #[inline]
    pub const fn nil() -> Self {
        Self { byte: 0, bits: 0 }
    }
}

impl fmt::Debug for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Nibble({:0width$b} / {})",
            self.byte,
            self.bits,
            width = self.bits as usize
        )
    }
}

impl From<(u8, u8)> for Nibble {
    fn from(value: (u8, u8)) -> Self {
        Self {
            byte: value.0,
            bits: value.1,
        }
    }
}

pub struct Nibbles<const N: usize> {
    bytes: [u8; N],
    cursor: u8,
    bits: u8,
}

impl<const N: usize> Nibbles<N> {
    #[inline]
    #[allow(dead_code)]
    const fn new(bytes: [u8; N], bits: u8) -> Self {
        debug_assert!(bits <= N as u8 * 8, "bits is too long");
        Self {
            bytes,
            cursor: 0,
            bits,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    #[inline]
    #[allow(dead_code)]
    pub const fn to_bytes(&self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> Iterator for Nibbles<N> {
    type Item = Nibble;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.bits {
            return None;
        }

        let bits = 4.min(self.bits - self.cursor);
        let byte = {
            let i = (self.cursor / 8) as usize;
            let b = self.bytes[i];
            let b = if self.cursor % 8 == 0 {
                b >> 4
            } else {
                b & 0x0f
            };
            b >> (4 - bits) << (4 - bits)
        };
        self.cursor += bits;

        Some(Nibble { bits, byte })
    }
}

impl From<Ipv4Addr> for Nibbles<4> {
    fn from(addr: Ipv4Addr) -> Self {
        let bytes = addr.octets();
        Self {
            bytes,
            cursor: 0,
            bits: 32,
        }
    }
}

impl From<Ipv4Cidr> for Nibbles<4> {
    fn from(cidr: Ipv4Cidr) -> Self {
        let bytes = cidr.octets();
        Self {
            bytes,
            cursor: 0,
            bits: cidr.bits(),
        }
    }
}

impl From<Ipv6Addr> for Nibbles<16> {
    fn from(addr: Ipv6Addr) -> Self {
        let bytes = addr.octets();
        Self {
            bytes,
            cursor: 0,
            bits: 128,
        }
    }
}

impl From<Ipv6Cidr> for Nibbles<16> {
    fn from(cidr: Ipv6Cidr) -> Self {
        let bytes = cidr.octets();
        Self {
            bytes,
            cursor: 0,
            bits: cidr.bits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_nibbles_iteration() {
        let tests = [
            (([0b1111_1111, 0, 0, 0], 0), vec![]),
            (([0b1111_1111, 0, 0, 0], 1), vec![(0b1000, 1)]),
            (([0b1111_1111, 0, 0, 0], 2), vec![(0b1100, 2)]),
            (([0b1100_1010, 0, 0, 0], 8), vec![(0b1100, 4), (0b1010, 4)]),
            (([0b1100_1010, 0, 0, 0], 6), vec![(0b1100, 4), (0b1000, 2)]),
            (([0b1100_1010, 0, 0, 0], 5), vec![(0b1100, 4), (0b1000, 1)]),
            (([0b1100_1010, 0, 0, 0], 4), vec![(0b1100, 4)]),
            (([0b1111_1010, 0, 0, 0], 3), vec![(0b1110, 3)]),
            (
                ([0b1111_1010, 0b1111_1111, 0, 0], 11),
                vec![(0b1111, 4), (0b1010, 4), (0b1110, 3)],
            ),
            (
                ([0b1010_0101, 0b1110_0111, 0, 0], 11),
                vec![(0b1010, 4), (0b0101, 4), (0b1110, 3)],
            ),
            (
                ([0b1010_0101, 0b1110_0111, 0, 0], 15),
                vec![(0b1010, 4), (0b0101, 4), (0b1110, 4), (0b0110, 3)],
            ),
        ];

        for (input, expected) in tests {
            let (bytes, bits) = input;
            let nibbles = Nibbles::new(bytes, bits);

            let actual: Vec<Nibble> = nibbles.collect();
            let expected: Vec<Nibble> = expected
                .into_iter()
                .map(|(byte, bits)| Nibble { byte, bits })
                .collect();
            assert_eq!(
                actual, expected,
                "input: {input:?} = {actual:?}, expected: {expected:?}"
            );
        }
    }

    #[test]
    fn test_ipv4_cidr_to_nibbles() {
        let tests = [
            ("0.0.0.0/0", vec![]),
            (
                "192.168.0.1/32",
                vec![
                    (0b1100, 4),
                    (0b0000, 4),
                    (0b1010, 4),
                    (0b1000, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0001, 4),
                ],
            ),
            (
                "192.168.0.0/16",
                vec![(0b1100, 4), (0b0000, 4), (0b1010, 4), (0b1000, 4)],
            ),
            (
                "192.168.223.0/24",
                vec![
                    (0b1100, 4),
                    (0b0000, 4),
                    (0b1010, 4),
                    (0b1000, 4),
                    (0b1101, 4),
                    (0b1111, 4),
                ],
            ),
            (
                "192.168.223.0/25",
                vec![
                    (0b1100, 4),
                    (0b0000, 4),
                    (0b1010, 4),
                    (0b1000, 4),
                    (0b1101, 4),
                    (0b1111, 4),
                    (0b0000, 1),
                ],
            ),
            (
                "192.168.223.0/18",
                vec![
                    (0b1100, 4),
                    (0b0000, 4),
                    (0b1010, 4),
                    (0b1000, 4),
                    (0b1100, 2),
                ],
            ),
            (
                "10.0.0.1/32",
                vec![
                    (0b0000, 4),
                    (0b1010, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0001, 4),
                ],
            ),
        ];

        for (s, expected) in tests {
            let cidr = s.parse::<Ipv4Cidr>().unwrap();
            let actual = Nibbles::from(cidr);
            let actual: Vec<Nibble> = actual.collect();
            let expected: Vec<Nibble> = expected
                .into_iter()
                .map(|(byte, bits)| Nibble { byte, bits })
                .collect();

            assert_eq!(
                actual, expected,
                "input: {s} = {actual:?}, expected: {expected:?}"
            );
        }
    }

    #[test]
    fn test_ipv6_cidr_to_nibbles() {
        let tests = [
            ("::/0", vec![]),
            (
                "2001:db8::/32",
                vec![
                    (0b0010, 4),
                    (0b0000, 4),
                    (0b0000, 4),
                    (0b0001, 4),
                    (0b0000, 4),
                    (0b1101, 4),
                    (0b1011, 4),
                    (0b1000, 4),
                ],
            ),
        ];
        for (s, expected) in tests {
            let cidr = s.parse::<Ipv6Cidr>().unwrap();
            let actual = Nibbles::from(cidr);
            let actual: Vec<Nibble> = actual.collect();
            let expected: Vec<Nibble> = expected
                .into_iter()
                .map(|(byte, bits)| Nibble { byte, bits })
                .collect();

            assert_eq!(
                actual, expected,
                "input: {s} = {actual:?}, expected: {expected:?}"
            );
        }
    }
}
