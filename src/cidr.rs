use core::fmt;
use core::hash::{Hash, Hasher};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use super::error::{CidrParseKind, Error, Result};

/// An IPv4 CIDR block.
///
/// IPv4 CIDR blocks are represented as an IPv4 address and a number of bits.
/// See [`Cidr`] for a type encompassing both IPv4 and IPv6 CIDR blocks.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv4Cidr;
///
/// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
/// assert_eq!("192.168.0.0/24".parse::<Ipv4Cidr>().unwrap(), cidr);
/// assert!("192.168.0.0".parse::<Ipv4Cidr>().is_err());
/// assert!("192.168.0.0/33".parse::<Ipv4Cidr>().is_err());
/// assert!("::/0".parse::<Ipv4Cidr>().is_err());
/// ```
#[derive(Copy, Clone)]
pub struct Ipv4Cidr {
    octets: [u8; 4],
    bits: u8,
}

impl Ipv4Cidr {
    /// The maximum number of bits in an IPv4 CIDR block.
    pub const MAX_BITS: u8 = 32;

    /// Returns the mask for the given number of bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// assert_eq!(Ipv4Cidr::mask_of(0), 0);
    /// ```
    pub const fn mask_of(bits: u8) -> u32 {
        if bits == 0 {
            return 0;
        }
        u32::MAX << (32 - bits)
    }

    /// Creates a new IPv4 CIDR block from four octets and a number of bits.
    ///
    /// The result will represent the IP address `octets` with the mask applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    ///
    /// assert_eq!(cidr.to_string(), "192.168.0.0/24".to_owned());
    /// ```
    #[inline]
    pub const fn new(octets: [u8; 4], bits: u8) -> Result<Self> {
        if bits > 32 {
            return Err(Error::OverflowIpv4CidrBit(bits));
        }

        let octets = (u32::from_be_bytes(octets) & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    /// Creates a new IPv4 CIDR block from an IP address and a number of bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::from_ip(Ipv4Addr::new(192, 168, 0, 0), 24).unwrap();
    /// ```
    #[inline]
    pub fn from_ip<I>(ip: I, bits: u8) -> Result<Self>
    where
        I: Into<Ipv4Addr>,
    {
        if bits > 32 {
            return Err(Error::OverflowIpv6CidrBit(bits));
        }

        let octets = (ip.into().to_bits() & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    /// Returns the IP address with the mask applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 1], 24).unwrap();
    /// assert_eq!(cidr.addr(), Ipv4Addr::new(192, 168, 0, 0)); // truncated
    /// ```
    #[inline]
    pub const fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(u32::from_be_bytes(self.octets))
    }

    /// Returns the mask for the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 1], 24).unwrap();
    /// assert_eq!(cidr.mask(), 0xff_ff_ff_00);
    #[inline]
    pub const fn mask(&self) -> u32 {
        Self::mask_of(self.bits)
    }

    /// Returns the four eight-bit integers that make up this CIDR.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 1], 24).unwrap();
    ///
    /// assert_eq!(cidr.octets(), [192, 168, 0, 0]);
    /// ```
    #[inline]
    pub const fn octets(&self) -> [u8; 4] {
        self.octets
    }

    /// Returns the number of bits in the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 1], 24).unwrap();
    ///
    /// assert_eq!(cidr.bits(), 24);
    /// ```
    #[inline]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Returns [`true`] if the CIDR block contains the given IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 1], 24).unwrap();
    ///
    /// assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 1)));
    /// assert!(!cidr.contains(Ipv4Addr::new(192, 168, 1, 1)));
    /// ```
    #[inline]
    pub const fn contains(&self, addr: Ipv4Addr) -> bool {
        let addr = addr.to_bits();
        let mask = self.mask();
        let cidr = u32::from_be_bytes(self.octets);

        addr & mask == cidr
    }

    /// Returns [`true`] if the CIDR block overlaps with the given CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr1 = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// let cidr2 = Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap();
    /// let cidr3 = Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap();
    ///
    /// assert!(!cidr1.overlaps(&cidr2));
    /// assert!(cidr1.overlaps(&cidr3));
    /// assert!(cidr2.overlaps(&cidr3));
    /// ```
    #[inline]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let min_bits = if self.bits < other.bits {
            self.bits
        } else {
            other.bits
        };
        let mask = Self::mask_of(min_bits);

        let x = u32::from_be_bytes(self.octets);
        let y = u32::from_be_bytes(other.octets);

        (x & mask) == (y & mask)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.octets), self.bits)
    }
}

impl fmt::Debug for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv4Cidr({self})")
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
    /// Creates a new IPv4 CIDR block from an IPv4 address with a mask of 32 bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::from(Ipv4Addr::new(192, 168, 0, 0));
    /// assert_eq!(cidr.bits(), 32)
    /// ```
    fn from(addr: Ipv4Addr) -> Self {
        Self::from_ip(addr, 32).unwrap()
    }
}

impl TryFrom<([u8; 4], u8)> for Ipv4Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 4], u8)) -> core::result::Result<Self, Self::Error> {
        Self::from_ip(octets, bits)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let (addr, bits) = s
            .split_once('/')
            .ok_or(Error::CidrParseError(CidrParseKind::Ipv4))?;
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::CidrParseError(CidrParseKind::Ipv4))?;
        let bits = bits
            .parse()
            .map_err(|_| Error::CidrParseError(CidrParseKind::Ipv4))?;

        Ipv4Cidr::from_ip(addr, bits)
    }
}

/// An IPv6 CIDR block.
///
/// IPv6 CIDR blocks are represented as an IPv6 address and a number of bits.
/// See [`Cidr`] for a type encompassing both IPv4 and IPv6 CIDR blocks.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv6Cidr;
///
/// let cidr = Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap();
/// assert_eq!(cidr.to_string(), "::/64".to_owned());
/// assert!("::/129".parse::<Ipv6Cidr>().is_err());
/// assert!("::1".parse::<Ipv6Cidr>().is_err());
/// assert!("192.168.0.0/24".parse::<Ipv6Cidr>().is_err());
/// ```
#[derive(Copy, Clone)]
pub struct Ipv6Cidr {
    octets: [u8; 16],
    bits: u8,
}

impl Ipv6Cidr {
    /// The maximum number of bits in an IPv6 CIDR block.
    pub const MAX_BITS: u8 = 128;

    /// Returns the mask for the given number of bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// assert_eq!(Ipv6Cidr::mask_of(0), 0);
    /// ```
    pub const fn mask_of(bits: u8) -> u128 {
        if bits == 0 {
            return 0;
        }
        u128::MAX << (128 - bits)
    }

    /// Creates a new IPv6 CIDR block from 16 octets and a number of bits.
    ///
    /// The result will represent the IP address `octets` with the mask applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap();
    /// assert_eq!(cidr.to_string(), "::/64".to_owned());
    /// ```
    #[inline]
    pub const fn new(octets: [u16; 8], bits: u8) -> Result<Self> {
        if bits > 128 {
            return Err(Error::OverflowIpv6CidrBit(bits));
        }

        let [a, b, c, d, e, f, g, h] = octets;
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

        let octets = unsafe { core::mem::transmute::<[u16; 8], [u8; 16]>(addr16) };
        let octets = (u128::from_be_bytes(octets) & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    /// Creates a new IPv6 CIDR block from an IP address and a number of bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::from_ip(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 64).unwrap();
    /// assert_eq!(cidr.to_string(), "::/64".to_owned());
    /// ```
    #[inline]
    pub fn from_ip<I>(ip: I, bits: u8) -> Result<Self>
    where
        I: Into<Ipv6Addr>,
    {
        if bits > 128 {
            return Err(Error::OverflowIpv6CidrBit(bits));
        }

        let octets = (ip.into().to_bits() & Self::mask_of(bits)).to_be_bytes();

        Ok(Self { octets, bits })
    }

    /// Returns the IP address with the mask applied.
    #[inline]
    pub const fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(u128::from_be_bytes(self.octets))
    }

    #[inline]
    pub const fn mask(&self) -> u128 {
        Self::mask_of(self.bits)
    }

    #[inline]
    pub const fn octets(&self) -> [u8; 16] {
        self.octets
    }

    #[inline]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn contains(&self, addr: Ipv6Addr) -> bool {
        let addr = addr.to_bits();
        let mask = self.mask();
        let cidr = u128::from_be_bytes(self.octets);

        addr & mask == cidr
    }

    #[inline]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let min_bits = if self.bits < other.bits {
            self.bits
        } else {
            other.bits
        };
        let mask = Self::mask_of(min_bits);

        let x = u128::from_be_bytes(self.octets);
        let y = u128::from_be_bytes(other.octets);

        (x & mask) == (y & mask)
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.octets), self.bits)
    }
}

impl fmt::Debug for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv6Cidr({self})")
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
    /// Creates a new IPv6 CIDR block from an IPv6 address with a mask of 128 bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    /// assert_eq!(cidr.bits(), 128);
    /// ```
    fn from(addr: Ipv6Addr) -> Self {
        Self::from_ip(addr, 128).unwrap()
    }
}

impl TryFrom<([u8; 16], u8)> for Ipv6Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 16], u8)) -> core::result::Result<Self, Self::Error> {
        Self::from_ip(octets, bits)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let (addr, bits) = s
            .split_once('/')
            .ok_or(Error::CidrParseError(CidrParseKind::Ipv6))?;
        let addr = addr
            .parse::<Ipv6Addr>()
            .map_err(|_| Error::CidrParseError(CidrParseKind::Ipv6))?;
        let bits = bits
            .parse()
            .map_err(|_| Error::CidrParseError(CidrParseKind::Ipv6))?;

        Ipv6Cidr::from_ip(addr, bits)
    }
}

/// An IP CIDR, either IPv4 or IPv6.
///
/// This enum can contain either an [`Ipv4Cidr`] or an [`Ipv6Cidr`], see their
/// respective documentation for more details.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl Cidr {
    pub fn from_ip<I>(ip: I, bits: u8) -> Result<Self>
    where
        I: Into<IpAddr>,
    {
        match ip.into() {
            IpAddr::V4(v4) => Ok(Cidr::V4(Ipv4Cidr::from_ip(v4, bits)?)),
            IpAddr::V6(v6) => Ok(Cidr::V6(Ipv6Cidr::from_ip(v6, bits)?)),
        }
    }

    /// Returns the IP address with the mask applied.
    pub const fn addr(&self) -> IpAddr {
        match self {
            Cidr::V4(v4) => IpAddr::V4(v4.addr()),
            Cidr::V6(v6) => IpAddr::V6(v6.addr()),
        }
    }

    #[inline]
    pub const fn bits(&self) -> u8 {
        match self {
            Cidr::V4(v4) => v4.bits(),
            Cidr::V6(v6) => v6.bits(),
        }
    }

    #[inline]
    pub const fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Cidr::V4(lh), IpAddr::V4(rh)) => lh.contains(rh),
            (Cidr::V6(lh), IpAddr::V6(rh)) => lh.contains(rh),
            _ => false,
        }
    }

    #[inline]
    pub const fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Cidr::V4(lh), Cidr::V4(rh)) => lh.overlaps(rh),
            (Cidr::V6(lh), Cidr::V6(rh)) => lh.overlaps(rh),
            _ => false,
        }
    }

    /// Returns [`true`] if the CIDR block is an [`IPv4` CIDR block], and [`false`] otherwise.
    ///
    /// [`IPv4` CIDR block]: Cidr::V4
    #[inline]
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, Cidr::V4(_))
    }

    /// Returns [`true`] if the CIDR block is an [`IPv6` CIDR block], and [`false`] otherwise.
    ///
    /// [`IPv6` CIDR block]: Cidr::V6
    #[inline]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, Cidr::V6(_))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cidr::V4(v4) => fmt::Display::fmt(&v4, f),
            Cidr::V6(v6) => fmt::Display::fmt(&v6, f),
        }
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cidr({self})")
    }
}

impl TryFrom<([u8; 4], u8)> for Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 4], u8)) -> core::result::Result<Self, Self::Error> {
        Ok(Cidr::V4(Ipv4Cidr::try_from((octets, bits))?))
    }
}

impl TryFrom<([u8; 16], u8)> for Cidr {
    type Error = Error;

    fn try_from((octets, bits): ([u8; 16], u8)) -> core::result::Result<Self, Self::Error> {
        Ok(Cidr::V6(Ipv6Cidr::try_from((octets, bits))?))
    }
}

impl From<Ipv4Cidr> for Cidr {
    fn from(v4: Ipv4Cidr) -> Self {
        Cidr::V4(v4)
    }
}

impl From<Ipv6Cidr> for Cidr {
    fn from(v6: Ipv6Cidr) -> Self {
        Cidr::V6(v6)
    }
}

impl PartialEq<Ipv4Cidr> for Cidr {
    fn eq(&self, other: &Ipv4Cidr) -> bool {
        match self {
            Cidr::V4(v4) => v4 == other,
            _ => false,
        }
    }
}

impl PartialEq<Cidr> for Ipv4Cidr {
    fn eq(&self, other: &Cidr) -> bool {
        match other {
            Cidr::V4(v4) => self == v4,
            _ => false,
        }
    }
}

impl PartialEq<Ipv6Cidr> for Cidr {
    fn eq(&self, other: &Ipv6Cidr) -> bool {
        match self {
            Cidr::V6(v6) => v6 == other,
            _ => false,
        }
    }
}

impl PartialEq<Cidr> for Ipv6Cidr {
    fn eq(&self, other: &Cidr) -> bool {
        match other {
            Cidr::V6(v6) => self == v6,
            _ => false,
        }
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

        Err(Error::CidrParseError(CidrParseKind::Ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_mask() {
        let tests = [
            (0, [0, 0, 0, 0]),
            (1, [0x80, 0, 0, 0]),
            (2, [0xc0, 0, 0, 0]),
            (3, [0xe0, 0, 0, 0]),
            (4, [0xf0, 0, 0, 0]),
            (5, [0xf8, 0, 0, 0]),
            (6, [0xfc, 0, 0, 0]),
            (7, [0xfe, 0, 0, 0]),
            (8, [0xff, 0, 0, 0]),
            (16, [0xff, 0xff, 0, 0]),
            (20, [0xff, 0xff, 0xf0, 0]),
            (24, [0xff, 0xff, 0xff, 0]),
            (32, [0xff, 0xff, 0xff, 0xff]),
        ];

        for (bit, expected) in tests {
            let expected = u32::from_be_bytes(expected);
            let actual = Ipv4Cidr::mask_of(bit);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    #[should_panic]
    fn test_ipv4_mask_overflow() {
        Ipv4Cidr::mask_of(33);
    }

    #[test]
    fn test_ipv6_mask() {
        let tests = [
            (0, [0x00; 16]),
            (
                1,
                [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
            ),
            (
                2,
                [
                    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
            ),
            (
                3,
                [
                    0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
            ),
            (128, [0xff; 16]),
        ];

        for (bit, expected) in tests {
            let expected = u128::from_be_bytes(expected);
            let actual = Ipv6Cidr::mask_of(bit);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    #[should_panic]
    fn test_ipv6_mask_overflow() {
        Ipv6Cidr::mask_of(129);
    }

    #[test]
    fn test_ipv4_cidr_contains() {
        {
            let ret = Ipv4Cidr::new([192, 168, 0, 1], 0);
            assert!(ret.is_ok());
            let cidr = ret.unwrap();
            assert_eq!(cidr.bits(), 0);
            assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(10, 10, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(172, 0, 0, 0)));
            assert!(cidr.contains(Ipv4Addr::new(0, 0, 0, 0)));
        }
        {
            let ret = Ipv4Cidr::new([192, 168, 0, 1], 24);
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
            let ret = Ipv4Cidr::new([192, 168, 24, 1], 24);
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
            let ret = Ipv4Cidr::new([192, 168, 24, 1], 16);
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
