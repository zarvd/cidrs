use core::fmt::{Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use super::{Error, Result};

#[derive(Copy, Clone)]
pub struct Ipv4Cidr {
    octets: [u8; 4],
    bits: u8,
}

impl Ipv4Cidr {
    pub const MAX_BITS: u8 = 32;

    /// Returns the mask for the given number of bits.
    ///
    /// # Examples:
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// assert_eq!(Ipv4Cidr::mask_of(0), 0);
    /// ```
    pub const fn mask_of(n: u8) -> u32 {
        if n == 0 {
            return 0;
        }
        u32::MAX << (32 - n)
    }

    #[inline(always)]
    pub fn new(a: u8, b: u8, c: u8, d: u8, bits: u8) -> Result<Self> {
        if bits > 32 {
            return Err(Error::InvalidMask {
                min: 0,
                max: 32,
                actual: bits,
            });
        }

        let octets = (u32::from_be_bytes([a, b, c, d]) & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    #[inline(always)]
    pub fn from_ip_bits(ip: u32, bits: u8) -> Result<Self> {
        if bits > 32 {
            return Err(Error::InvalidMask {
                min: 0,
                max: 32,
                actual: bits,
            });
        }

        let octets = (ip & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    #[inline(always)]
    pub fn from_ip(ip: Ipv4Addr, bits: u8) -> Result<Self> {
        Self::from_ip_bits(ip.to_bits(), bits)
    }

    /// Returns the IP address with the mask applied.
    #[inline(always)]
    pub fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.octets)
    }

    #[inline]
    pub fn masked(&self) -> u32 {
        u32::from_be_bytes(self.octets) & Self::mask_of(self.bits)
    }

    /// Returns the mask for the CIDR block.
    #[inline(always)]
    pub fn mask(&self) -> u32 {
        Self::mask_of(self.bits)
    }

    #[inline(always)]
    pub fn octets(&self) -> [u8; 4] {
        self.octets
    }

    #[inline(always)]
    pub fn bits(&self) -> u8 {
        self.bits
    }

    #[inline(always)]
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let addr = addr.to_bits();
        let mask = self.mask();
        let cidr = u32::from_be_bytes(self.octets);

        addr & mask == cidr
    }

    #[inline(always)]
    pub fn overlaps(&self, other: &Self) -> bool {
        let min_bits = self.bits.min(other.bits);
        let mask = Self::mask_of(min_bits);

        let x = u32::from_be_bytes(self.octets);
        let y = u32::from_be_bytes(other.octets);

        (x & mask) == (y & mask)
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.octets), self.bits)
    }
}

impl Debug for Ipv4Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ipv4Cidr({})", self)
    }
}

impl PartialEq for Ipv4Cidr {
    fn eq(&self, other: &Self) -> bool {
        self.octets == other.octets && self.bits == other.bits
    }
}

impl Eq for Ipv4Cidr {}

impl Hash for Ipv4Cidr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.octets.hash(state);
        self.bits.hash(state);
    }
}

impl From<Ipv4Addr> for Ipv4Cidr {
    fn from(addr: Ipv4Addr) -> Self {
        Self::from_ip(addr, 32).unwrap()
    }
}

impl TryFrom<([u8; 4], u8)> for Ipv4Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 4], u8)) -> std::result::Result<Self, Self::Error> {
        Self::from_ip_bits(u32::from_be_bytes(octets), bits)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let (addr, bits) = s.split_once('/').ok_or(Error::ParseError)?;
        Ipv4Cidr::from_ip(
            addr.parse().map_err(|_| Error::ParseError)?,
            bits.parse().map_err(|_| Error::ParseError)?,
        )
    }
}

#[derive(Copy, Clone)]
pub struct Ipv6Cidr {
    octets: [u8; 16],
    bits: u8,
}

impl Ipv6Cidr {
    pub const MAX_BITS: u8 = 128;

    /// Returns the mask for the given number of bits.
    ///
    /// # Examples:
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// assert_eq!(Ipv6Cidr::mask_of(0), 0);
    /// ```
    pub const fn mask_of(n: u8) -> u128 {
        if n == 0 {
            return 0;
        }
        u128::MAX << (128 - n)
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        a: u16,
        b: u16,
        c: u16,
        d: u16,
        e: u16,
        f: u16,
        g: u16,
        h: u16,
        bits: u8,
    ) -> Result<Self> {
        if bits > 128 {
            return Err(Error::InvalidMask {
                min: 0,
                max: 128,
                actual: bits,
            });
        }

        let addr16 = [
            a.to_be(),
            b.to_be(),
            c.to_be(),
            d.to_be(),
            e.to_be(),
            f.to_be(),
            g.to_be(),
            h.to_be(),
        ];

        use core::mem::transmute;
        let octets = unsafe { transmute::<[u16; 8], [u8; 16]>(addr16) };

        let octets = (u128::from_be_bytes(octets) & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    #[inline(always)]
    pub fn from_ip_bits(ip: u128, bits: u8) -> Result<Self> {
        if bits > 128 {
            return Err(Error::InvalidMask {
                min: 0,
                max: 128,
                actual: bits,
            });
        }

        let octets = (ip & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    #[inline(always)]
    pub fn from_ip(ip: Ipv6Addr, bits: u8) -> Result<Self> {
        Self::from_ip_bits(ip.to_bits(), bits)
    }

    /// Returns the IP address with the mask applied.
    #[inline(always)]
    pub fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.octets)
    }

    #[inline(always)]
    pub fn mask(&self) -> u128 {
        Self::mask_of(self.bits)
    }

    #[inline(always)]
    pub fn octets(&self) -> [u8; 16] {
        self.octets
    }

    #[inline(always)]
    pub fn bits(&self) -> u8 {
        self.bits
    }

    #[inline(always)]
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        let addr = addr.to_bits();
        let mask = self.mask();
        let cidr = u128::from_be_bytes(self.octets);

        addr & mask == cidr
    }

    #[inline(always)]
    pub fn overlaps(&self, other: &Self) -> bool {
        let min_bits = self.bits.min(other.bits);
        let mask = Self::mask_of(min_bits);

        let x = u128::from_be_bytes(self.octets);
        let y = u128::from_be_bytes(other.octets);

        (x & mask) == (y & mask)
    }
}

impl Display for Ipv6Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.octets), self.bits)
    }
}

impl Debug for Ipv6Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ipv6Cidr({})", self)
    }
}

impl PartialEq for Ipv6Cidr {
    fn eq(&self, other: &Self) -> bool {
        self.octets == other.octets && self.bits == other.bits
    }
}

impl Eq for Ipv6Cidr {}

impl Hash for Ipv6Cidr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.octets.hash(state);
        self.bits.hash(state);
    }
}

impl From<Ipv6Addr> for Ipv6Cidr {
    fn from(addr: Ipv6Addr) -> Self {
        Self::from_ip(addr, 128).unwrap()
    }
}

impl TryFrom<([u8; 16], u8)> for Ipv6Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 16], u8)) -> std::result::Result<Self, Self::Error> {
        Self::from_ip_bits(u128::from_be_bytes(octets), bits)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let (addr, bits) = s.split_once('/').ok_or(Error::ParseError)?;
        Ipv6Cidr::from_ip(
            addr.parse().map_err(|_| Error::ParseError)?,
            bits.parse().map_err(|_| Error::ParseError)?,
        )
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl Cidr {
    pub fn from_ip(ip: IpAddr, bits: u8) -> Result<Self> {
        match ip {
            IpAddr::V4(v4) => Ok(Cidr::V4(Ipv4Cidr::from_ip(v4, bits)?)),
            IpAddr::V6(v6) => Ok(Cidr::V6(Ipv6Cidr::from_ip(v6, bits)?)),
        }
    }

    /// Returns the IP address with the mask applied.
    pub fn addr(&self) -> IpAddr {
        match self {
            Cidr::V4(v4) => IpAddr::V4(v4.addr()),
            Cidr::V6(v6) => IpAddr::V6(v6.addr()),
        }
    }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4(v4) => Display::fmt(&v4, f),
            Cidr::V6(v6) => Display::fmt(&v6, f),
        }
    }
}

impl TryFrom<([u8; 4], u8)> for Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 4], u8)) -> std::result::Result<Self, Self::Error> {
        Ok(Cidr::V4(Ipv4Cidr::try_from((octets, bits))?))
    }
}

impl TryFrom<([u8; 16], u8)> for Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 16], u8)) -> std::result::Result<Self, Self::Error> {
        Ok(Cidr::V6(Ipv6Cidr::try_from((octets, bits))?))
    }
}

impl FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        if let Ok(v4) = s.parse::<Ipv4Cidr>() {
            return Ok(Cidr::V4(v4));
        }

        if let Ok(v6) = s.parse::<Ipv6Cidr>() {
            return Ok(Cidr::V6(v6));
        }

        Err(Error::ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4_mask() {
        let cases = [
            (0, Ipv4Addr::new(0, 0, 0, 0)),
            (8, Ipv4Addr::new(255, 0, 0, 0)),
            (16, Ipv4Addr::new(255, 255, 0, 0)),
            (24, Ipv4Addr::new(255, 255, 255, 0)),
            (32, Ipv4Addr::new(255, 255, 255, 255)),
        ];

        for (bit, expected) in cases {
            assert_eq!(Ipv4Addr::from(Ipv4Cidr::mask_of(bit)), expected);
        }
    }

    #[test]
    fn test_v6_mask() {
        let cases = [
            (0, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            (16, Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0)),
            (32, Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)),
            (48, Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0)),
            (
                64,
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
            ),
            (
                80,
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0),
            ),
            (
                96,
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0),
            ),
            (
                112,
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0),
            ),
            (
                128,
                Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ),
            ),
        ];

        for (bit, expected) in cases {
            assert_eq!(Ipv6Addr::from(Ipv6Cidr::mask_of(bit)), expected);
        }
    }

    #[test]
    fn test_cidr_v4() {
        {
            let ret = Ipv4Cidr::new(192, 168, 0, 1, 0);
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 0);
            assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(10, 10, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(172, 0, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(0, 0, 0, 0)));
        }
        {
            let ret = Ipv4Cidr::new(192, 168, 0, 1, 24);
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 24);
            for i in 0..=255 {
                assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, i)));
            }
            assert!(!cidr.contains(Ipv4Addr::new(192, 168, 1, 0)));
            assert!(!cidr.contains(Ipv4Addr::new(192, 168, 2, 0)));
            assert!(!cidr.contains(Ipv4Addr::new(192, 168, 1, 255)));
        }

        {
            let ret = Ipv4Cidr::new(192, 168, 24, 1, 24);
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 24);
            for i in 0..=255 {
                assert!(cidr.contains(Ipv4Addr::new(192, 168, 24, i)));
            }
            assert!(!cidr.contains(Ipv4Addr::new(192, 168, 23, 0)));
            assert!(!cidr.contains(Ipv4Addr::new(192, 168, 25, 255)));
            assert!(!cidr.contains(Ipv4Addr::new(192, 0, 0, 0)));
            assert!(!cidr.contains(Ipv4Addr::new(192, 167, 255, 255)));
        }

        {
            let ret = Ipv4Cidr::new(192, 168, 24, 1, 16);
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 16);
        }
    }

    #[test]
    fn test_cidr_v6() {
        {
            let ret = Ipv6Cidr::from_str("::/0");
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 0);
        }
    }
}
