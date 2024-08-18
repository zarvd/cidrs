use crate::{Ipv4Cidr, Ipv6Cidr};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Nibble {
    pub value: u8,
    pub len: u8,
}

impl Nibble {
    #[inline]
    pub const fn nil() -> Self {
        Self { value: 0, len: 0 }
    }

    #[inline]
    pub const fn from_octet(octet: u8, len: u8) -> Self {
        debug_assert!(octet < 16);
        debug_assert!(len <= 4);

        let shift = 4 - len;
        let octet = octet >> shift << shift;

        Self { value: octet, len }
    }

    pub fn from_octets(octets: &[u8], len: u8) -> Vec<Self> {
        let mut nibbles = Vec::new();

        let mut shift = 0;
        while shift < len {
            let i = (shift / 8) as usize;
            let octet = if shift % 8 == 0 {
                octets[i] >> 4
            } else {
                octets[i] & 0xf
            };

            let l = if len - shift >= 4 { 4 } else { len - shift };

            nibbles.push(Self::from_octet(octet, l));

            shift += 4;
        }

        nibbles
    }
}

pub(crate) struct Nibbles(Vec<Nibble>);

impl Nibbles {
    #[inline]
    pub fn into_vec(self) -> Vec<Nibble> {
        self.0
    }
}

impl From<Ipv4Cidr> for Nibbles {
    fn from(cidr: Ipv4Cidr) -> Self {
        let mut bytes = cidr.octets().into_iter();
        let mut nibbles = {
            let cap = cidr.bits() as usize / 4 + if cidr.bits() % 4 == 0 { 0 } else { 1 };
            Vec::with_capacity(cap)
        };
        let mut bits = cidr.bits();
        debug_assert!(bits <= 32);
        while bits > 0 {
            let byte = bytes.next().unwrap();
            let (lh, rh) = (byte >> 4, byte & 0b0000_1111);
            nibbles.push(Nibble {
                value: lh,
                len: 4.min(bits),
            });
            if bits <= 4 {
                break;
            }
            bits -= 4;
            nibbles.push(Nibble {
                value: rh,
                len: 4.min(bits),
            });
            bits -= 4.min(bits);
        }
        Nibbles(nibbles)
    }
}

impl From<Ipv6Cidr> for Nibbles {
    fn from(cidr: Ipv6Cidr) -> Self {
        Nibbles(Nibble::from_octets(&cidr.octets(), cidr.bits()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_from_octets() {
        let tests = [
            ((vec![0b1111_1111], 0), vec![]),
            (
                (vec![0b1111_1111], 1),
                vec![Nibble {
                    value: 0b1000,
                    len: 1,
                }],
            ),
            (
                (vec![0b1111_1111], 2),
                vec![Nibble {
                    value: 0b1100,
                    len: 2,
                }],
            ),
            (
                (vec![0b1100_1010], 8),
                vec![
                    Nibble {
                        value: 0b1100,
                        len: 4,
                    },
                    Nibble {
                        value: 0b1010,
                        len: 4,
                    },
                ],
            ),
            (
                (vec![0b1100_1010], 6),
                vec![
                    Nibble {
                        value: 0b1100,
                        len: 4,
                    },
                    Nibble {
                        value: 0b1000,
                        len: 2,
                    },
                ],
            ),
            (
                (vec![0b1100_1010], 5),
                vec![
                    Nibble {
                        value: 0b1100,
                        len: 4,
                    },
                    Nibble {
                        value: 0b1000,
                        len: 1,
                    },
                ],
            ),
            (
                (vec![0b1100_1010], 4),
                vec![Nibble {
                    value: 0b1100,
                    len: 4,
                }],
            ),
            (
                (vec![0b1111_1010], 3),
                vec![Nibble {
                    value: 0b1110,
                    len: 3,
                }],
            ),
            (
                (vec![0b1111_1010, 0b1111_1111], 11),
                vec![
                    Nibble {
                        value: 0b1111,
                        len: 4,
                    },
                    Nibble {
                        value: 0b1010,
                        len: 4,
                    },
                    Nibble {
                        value: 0b1110,
                        len: 3,
                    },
                ],
            ),
        ];

        for (input, expected) in tests {
            let actual = Nibble::from_octets(&input.0, input.1);
            assert_eq!(
                actual,
                expected,
                "input: ({}, {})",
                input
                    .0
                    .into_iter()
                    .map(|v| format!("{:10b}", v))
                    .collect::<Vec<_>>()
                    .join(", "),
                input.1
            );
        }
    }

    #[test]
    fn test_ipv4_cidr_key_to_nibbles() {
        let tests = [
            ("0.0.0.0/0", vec![]),
            (
                "192.168.0.1/32",
                vec![
                    Nibble { value: 12, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 8, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 1, len: 4 },
                ],
            ),
            (
                "192.168.0.0/16",
                vec![
                    Nibble { value: 12, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 8, len: 4 },
                ],
            ),
            (
                "192.168.223.0/24",
                vec![
                    Nibble { value: 12, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 8, len: 4 },
                    Nibble { value: 13, len: 4 },
                    Nibble { value: 15, len: 4 },
                ],
            ),
            (
                "192.168.223.0/25",
                vec![
                    Nibble { value: 12, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 8, len: 4 },
                    Nibble { value: 13, len: 4 },
                    Nibble { value: 15, len: 4 },
                    Nibble { value: 0, len: 1 },
                ],
            ),
            (
                "192.168.223.0/18",
                vec![
                    Nibble { value: 12, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 8, len: 4 },
                    Nibble { value: 12, len: 2 },
                ],
            ),
            (
                "10.0.0.1/32",
                vec![
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 10, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 0, len: 4 },
                    Nibble { value: 1, len: 4 },
                ],
            ),
        ];

        for (s, expected) in tests {
            let cidr = s.parse::<Ipv4Cidr>().unwrap();
            let actual = Nibbles::from(cidr);
            assert_eq!(actual.0, expected, "cidr: {}", cidr);
        }
    }
}
