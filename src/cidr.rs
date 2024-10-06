use core::cmp::Ordering;
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
        if bits > 32 {
            panic!("bits must be <= 32");
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

    /// Returns the network address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// assert_eq!(cidr.network_addr(), Ipv4Addr::new(192, 168, 0, 0));
    /// ```
    #[inline]
    pub const fn network_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(u32::from_be_bytes(self.octets))
    }

    /// Returns the broadcast address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// assert_eq!(cidr.broadcast_addr(), Ipv4Addr::new(192, 168, 0, 255));
    /// ```
    #[inline]
    pub const fn broadcast_addr(&self) -> Ipv4Addr {
        let mask = Self::mask_of(self.bits);
        let network = u32::from_be_bytes(self.octets);
        Ipv4Addr::from_bits(network | !mask)
    }

    /// Returns an iterator over the usable host addresses in the network.
    /// For networks with a mask length of 31 or 32, all addresses are included.
    /// For networks with a mask length less than 31, the network address and broadcast address are excluded.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    /// use cidrs::Ipv4Cidr;
    ///
    /// // Example with /24 network (256 addresses)
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// let mut hosts = cidr.hosts();
    ///
    /// assert_eq!(hosts.next(), Some(Ipv4Addr::new(192, 168, 0, 1)));
    /// assert_eq!(hosts.next(), Some(Ipv4Addr::new(192, 168, 0, 2)));
    /// // ... more addresses ...
    /// assert_eq!(hosts.last(), Some(Ipv4Addr::new(192, 168, 0, 254)));
    ///
    /// // Example with /31 network (2 addresses)
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 31).unwrap();
    /// let mut hosts = cidr.hosts();
    ///
    /// assert_eq!(hosts.next(), Some(Ipv4Addr::new(192, 168, 0, 0)));
    /// assert_eq!(hosts.next(), Some(Ipv4Addr::new(192, 168, 0, 1)));
    /// assert_eq!(hosts.next(), None);
    /// ```
    #[inline]
    pub const fn hosts(&self) -> Ipv4Hosts {
        let min = u32::from_be_bytes(self.octets);
        let max = min + (u32::MAX ^ Self::mask_of(self.bits));
        let end = if max == u32::MAX { None } else { Some(max) };

        if self.bits >= 31 {
            Ipv4Hosts {
                cursor: min,
                end: if let Some(v) = end { Some(v + 1) } else { None },
            }
        } else {
            Ipv4Hosts {
                cursor: min + 1,
                end: if let Some(v) = end {
                    Some(v)
                } else {
                    Some(u32::MAX)
                },
            }
        }
    }

    /// Returns the supernet of this CIDR block, if possible.
    ///
    /// The supernet is the next larger network that contains this CIDR block.
    /// If the current CIDR block has 0 bits (representing the entire IPv4 address space),
    /// this method returns `None` as there is no larger network possible.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// let supernet = cidr.supernet().unwrap();
    /// assert_eq!(supernet, Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap());
    ///
    /// let entire_space = Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap();
    /// assert_eq!(entire_space.supernet(), None);
    /// ```
    #[inline]
    pub fn supernet(&self) -> Option<Ipv4Cidr> {
        match self.bits() {
            0 => None,
            bits => Some(Ipv4Cidr::new(self.octets(), bits - 1).unwrap()),
        }
    }

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

    /// Returns [`true`] if the CIDR block contains the given CIDR block.
    ///
    /// # Example
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr1 = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
    /// let cidr2 = Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap();
    /// let cidr3 = Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap();
    ///
    /// assert!(!cidr1.contains_cidr(&cidr2));
    /// assert!(!cidr2.contains_cidr(&cidr1));
    /// assert!(!cidr1.contains_cidr(&cidr3));
    /// assert!(!cidr2.contains_cidr(&cidr3));
    /// assert!(cidr3.contains_cidr(&cidr1));
    /// assert!(cidr3.contains_cidr(&cidr2));
    /// ```
    #[inline]
    pub const fn contains_cidr(&self, other: &Self) -> bool {
        self.overlaps(other) && self.bits() <= other.bits
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

/// Implements partial ordering for `Ipv4Cidr`.
///
/// This implementation delegates to the `Ord` implementation.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv4Cidr;
/// use std::cmp::Ordering;
///
/// let cidr1 = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
/// let cidr2 = Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap();
/// let cidr3 = Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap();
///
/// assert_eq!(cidr1.partial_cmp(&cidr2), Some(Ordering::Greater));
/// assert_eq!(cidr1.partial_cmp(&cidr3), Some(Ordering::Less));
/// assert_eq!(cidr3.partial_cmp(&cidr1), Some(Ordering::Greater));
/// ```
impl PartialOrd for Ipv4Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements total ordering for `Ipv4Cidr`.
///
/// CIDRs are first compared by their network address, then by their prefix length.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv4Cidr;
/// use std::cmp::Ordering;
///
/// let cidr1 = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
/// let cidr2 = Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap();
/// let cidr3 = Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap();
///
/// assert_eq!(cidr1.cmp(&cidr2), Ordering::Greater);
/// assert_eq!(cidr1.cmp(&cidr3), Ordering::Less);
/// assert_eq!(cidr3.cmp(&cidr1), Ordering::Greater);
/// ```
impl Ord for Ipv4Cidr {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = u32::from_be_bytes(self.octets);
        let b = u32::from_be_bytes(other.octets);

        match a.cmp(&b) {
            Ordering::Equal => self.bits.cmp(&other.bits),
            ord => ord,
        }
    }
}

pub struct Ipv4Hosts {
    cursor: u32,
    end: Option<u32>,
}

impl Ipv4Hosts {
    /// Returns the number of IPv4 addresses in the range.
    ///
    /// This method calculates the total number of IPv4 addresses between the current cursor
    /// position and the end of the range. If there's no defined end (i.e., the range extends
    /// to the maximum possible IPv4 address), it returns the number of addresses from the
    /// cursor to the end of the IPv4 address space.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4Cidr;
    ///
    /// let cidr: Ipv4Cidr = "192.168.0.0/24".parse().unwrap();
    /// let hosts = cidr.hosts();
    /// assert_eq!(hosts.len(), 254);
    ///
    /// let cidr: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    /// let hosts = cidr.hosts();
    /// assert_eq!(hosts.len(), 16777214);
    /// ```
    #[inline]
    pub const fn len(&self) -> u32 {
        debug_assert!(!(self.end.is_none() && self.cursor == 0));

        match self.end {
            Some(end) => end - self.cursor,
            None => u32::MAX - self.cursor + 1,
        }
    }
}

impl Iterator for Ipv4Hosts {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end.is_some_and(|end| self.cursor >= end) {
            return None;
        }

        let rv = Some(Ipv4Addr::from_bits(self.cursor));

        if self.cursor < u32::MAX {
            self.cursor += 1;
        } else {
            self.end = Some(u32::MAX); // as a stop mark
        }

        rv
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n: u32 = self.len();
        usize::try_from(n).map_or((usize::MAX, None), |n| (n, Some(n)))
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.size_hint().1.expect("count overflow")
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
        if bits > 128 {
            panic!("bits must be <= 128");
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

    /// Returns the network address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32).unwrap();
    /// assert_eq!(cidr.network_addr(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    /// ```
    #[inline]
    pub const fn network_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_bits(u128::from_be_bytes(self.octets))
    }

    /// Returns the broadcast address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32).unwrap();
    /// assert_eq!(cidr.broadcast_addr(), Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff));
    /// ```
    #[inline]
    pub const fn broadcast_addr(&self) -> Ipv6Addr {
        let mask = Self::mask_of(self.bits);
        let network = u128::from_be_bytes(self.octets);
        Ipv6Addr::from_bits(network | !mask)
    }

    /// Returns an iterator over the usable host addresses in the network.
    /// For networks with a mask length of 127 or 128, all addresses are included.
    /// For networks with a mask length less than 127, the network address and broadcast address are excluded.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    /// use cidrs::Ipv6Cidr;
    ///
    /// // Example with /126 network (4 addresses)
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 126).unwrap();
    /// let mut hosts = cidr.hosts();
    ///
    /// assert_eq!(hosts.next(), Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    /// assert_eq!(hosts.next(), Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)));
    /// assert_eq!(hosts.next(), None);
    ///
    /// // Example with /127 network (2 addresses)
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 127).unwrap();
    /// let mut hosts = cidr.hosts();
    ///
    /// assert_eq!(hosts.next(), Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
    /// assert_eq!(hosts.next(), Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    /// assert_eq!(hosts.next(), None);
    /// ```
    #[inline]
    pub const fn hosts(&self) -> Ipv6Hosts {
        let min = u128::from_be_bytes(self.octets);
        let max = min + (u128::MAX ^ Self::mask_of(self.bits));
        let end = if max == u128::MAX { None } else { Some(max) };

        if self.bits >= 127 {
            Ipv6Hosts {
                cursor: min,
                end: if let Some(v) = end { Some(v + 1) } else { None },
            }
        } else {
            Ipv6Hosts {
                cursor: min + 1,
                end: if let Some(v) = end {
                    Some(v)
                } else {
                    Some(u128::MAX)
                },
            }
        }
    }

    /// Returns the supernet of this CIDR block, if possible.
    ///
    /// The supernet is the next larger network that contains this CIDR block.
    /// If the current CIDR block has 0 bits (representing the entire IPv6 address space),
    /// this method returns `None` as there is no larger network possible.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap();
    /// let supernet = cidr.supernet().unwrap();
    /// assert_eq!(supernet, Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 47).unwrap());
    ///
    /// let entire_space = Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 0).unwrap();
    /// assert_eq!(entire_space.supernet(), None);
    /// ```
    #[inline]
    pub fn supernet(&self) -> Option<Ipv6Cidr> {
        match self.bits() {
            0 => None,
            bits => Some(Ipv6Cidr::from_ip(self.network_addr(), bits - 1).unwrap()),
        }
    }

    /// Returns the subnet mask of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
    /// assert_eq!(cidr.mask(), 0xffffffffffffffff0000000000000000);
    /// ```
    #[inline]
    pub const fn mask(&self) -> u128 {
        Self::mask_of(self.bits)
    }

    /// Returns the sixteen eight-bit integers that make up this CIDR.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 64).unwrap();
    /// assert_eq!(cidr.octets(), [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// ```
    #[inline]
    pub const fn octets(&self) -> [u8; 16] {
        self.octets
    }

    /// Returns the number of bits in the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
    /// assert_eq!(cidr.bits(), 64);
    /// ```
    #[inline]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Returns [`true`] if the CIDR block contains the given IPv6 address.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
    ///
    /// assert!(cidr.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    /// assert!(!cidr.contains(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)));
    /// ```
    #[inline]
    pub const fn contains(&self, addr: Ipv6Addr) -> bool {
        let addr = addr.to_bits();
        let mask = self.mask();
        let cidr = u128::from_be_bytes(self.octets);

        addr & mask == cidr
    }

    /// Returns [`true`] if the CIDR block contains the given CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr1 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
    /// let cidr2 = Ipv6Cidr::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0], 64).unwrap();
    /// let cidr3 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32).unwrap();
    ///
    /// assert!(!cidr1.contains_cidr(&cidr2));
    /// assert!(!cidr2.contains_cidr(&cidr1));
    /// assert!(!cidr1.contains_cidr(&cidr3));
    /// assert!(!cidr2.contains_cidr(&cidr3));
    /// assert!(cidr3.contains_cidr(&cidr1));
    /// assert!(cidr3.contains_cidr(&cidr2));
    /// ```
    #[inline]
    pub const fn contains_cidr(&self, other: &Self) -> bool {
        self.overlaps(other) && self.bits() <= other.bits
    }

    /// Returns [`true`] if the CIDR block overlaps with the given CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr1 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
    /// let cidr2 = Ipv6Cidr::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0], 64).unwrap();
    /// let cidr3 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32).unwrap();
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

/// Implements partial ordering for `Ipv6Cidr`.
///
/// This implementation delegates to the `Ord` implementation.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv6Cidr;
/// use std::cmp::Ordering;
///
/// let cidr1 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap();
/// let cidr2 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
/// let cidr3 = Ipv6Cidr::new([0x2001, 0xdb9, 0, 0, 0, 0, 0, 0], 48).unwrap();
///
/// assert_eq!(cidr1.partial_cmp(&cidr2), Some(Ordering::Less));
/// assert_eq!(cidr1.partial_cmp(&cidr3), Some(Ordering::Less));
/// assert_eq!(cidr3.partial_cmp(&cidr1), Some(Ordering::Greater));
/// ```
impl PartialOrd for Ipv6Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements total ordering for `Ipv6Cidr`.
///
/// CIDRs are first compared by their network address, then by their prefix length.
///
/// # Examples
///
/// ```
/// use cidrs::Ipv6Cidr;
/// use std::cmp::Ordering;
///
/// let cidr1 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap();
/// let cidr2 = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 64).unwrap();
/// let cidr3 = Ipv6Cidr::new([0x2001, 0xdb9, 0, 0, 0, 0, 0, 0], 48).unwrap();
///
/// assert_eq!(cidr1.cmp(&cidr2), Ordering::Less);
/// assert_eq!(cidr1.cmp(&cidr3), Ordering::Less);
/// assert_eq!(cidr3.cmp(&cidr1), Ordering::Greater);
/// ```
impl Ord for Ipv6Cidr {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = u128::from_be_bytes(self.octets);
        let b = u128::from_be_bytes(other.octets);

        match a.cmp(&b) {
            Ordering::Equal => self.bits.cmp(&other.bits),
            ord => ord,
        }
    }
}

pub struct Ipv6Hosts {
    cursor: u128,
    end: Option<u128>,
}

impl Ipv6Hosts {
    /// Returns the number of IPv6 addresses in the range.
    ///
    /// This method calculates the total number of IPv6 addresses between the current cursor
    /// position and the end of the range. If there's no defined end (i.e., the range extends
    /// to the maximum possible IPv6 address), it returns the number of addresses from the
    /// cursor to the end of the IPv6 address space.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6Cidr;
    ///
    /// let cidr: Ipv6Cidr = "2001:db8::/120".parse().unwrap();
    /// let hosts = cidr.hosts();
    /// assert_eq!(hosts.len(), 254);
    ///
    /// let cidr: Ipv6Cidr = "2001:db8::/64".parse().unwrap();
    /// let hosts = cidr.hosts();
    /// assert_eq!(hosts.len(), 18446744073709551614);
    /// ```
    #[inline]
    pub const fn len(&self) -> u128 {
        debug_assert!(!(self.end.is_none() && self.cursor == 0));

        match self.end {
            Some(end) => end - self.cursor,
            None => u128::MAX - self.cursor + 1,
        }
    }
}

impl Iterator for Ipv6Hosts {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end.is_some_and(|end| self.cursor >= end) {
            return None;
        }

        let rv = Some(Ipv6Addr::from_bits(self.cursor));

        if self.cursor < u128::MAX {
            self.cursor += 1;
        } else {
            self.end = Some(u128::MAX); // as a stop mark
        }

        rv
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n: u128 = self.len();
        usize::try_from(n).map_or((usize::MAX, None), |n| (n, Some(n)))
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.size_hint().1.expect("count overflow")
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
    /// Creates a new `Cidr` from an IP address and a number of bits.
    ///
    /// This function will create either an IPv4 or IPv6 CIDR block depending on the type of IP address provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use std::str::FromStr;
    /// use cidrs::Cidr;
    ///
    /// // Creating an IPv4 CIDR
    /// let ipv4_addr = IpAddr::from_str("192.168.0.1").unwrap();
    /// let ipv4_cidr = Cidr::new(ipv4_addr, 24).unwrap();
    /// assert_eq!(ipv4_cidr.to_string(), "192.168.0.0/24");
    ///
    /// // Creating an IPv6 CIDR
    /// let ipv6_addr = IpAddr::from_str("2001:db8::1").unwrap();
    /// let ipv6_cidr = Cidr::new(ipv6_addr, 64).unwrap();
    /// assert_eq!(ipv6_cidr.to_string(), "2001:db8::/64");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the number of bits is invalid for the given IP version.
    pub fn new<I>(ip: I, bits: u8) -> Result<Self>
    where
        I: Into<IpAddr>,
    {
        match ip.into() {
            IpAddr::V4(v4) => Ok(Cidr::V4(Ipv4Cidr::from_ip(v4, bits)?)),
            IpAddr::V6(v6) => Ok(Cidr::V6(Ipv6Cidr::from_ip(v6, bits)?)),
        }
    }

    /// Returns the network address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 24).unwrap();
    /// assert_eq!(ipv4_cidr.network_addr(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 32).unwrap();
    /// assert_eq!(ipv6_cidr.network_addr(), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
    /// ```
    pub const fn network_addr(&self) -> IpAddr {
        match self {
            Cidr::V4(v4) => IpAddr::V4(v4.network_addr()),
            Cidr::V6(v6) => IpAddr::V6(v6.network_addr()),
        }
    }

    /// Returns the broadcast address of the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 24).unwrap();
    /// assert_eq!(ipv4_cidr.broadcast_addr(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)));
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 32).unwrap();
    /// assert_eq!(ipv6_cidr.broadcast_addr(), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)));
    /// ```
    pub const fn broadcast_addr(&self) -> IpAddr {
        match self {
            Cidr::V4(v4) => IpAddr::V4(v4.broadcast_addr()),
            Cidr::V6(v6) => IpAddr::V6(v6.broadcast_addr()),
        }
    }

    /// Returns an iterator over the usable host addresses in the network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv6Addr};
    ///
    /// use cidrs::{Cidr, Ipv6Cidr};
    ///
    /// let cidr = Cidr::V6(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 127).unwrap());
    /// let mut hosts = cidr.hosts();
    ///
    /// assert_eq!(
    ///     hosts.next(),
    ///     Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
    /// );
    /// assert_eq!(
    ///     hosts.next(),
    ///     Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
    /// );
    /// assert_eq!(hosts.next(), None);
    /// ```
    pub const fn hosts(&self) -> Hosts {
        match self {
            Cidr::V4(v4) => Hosts::V4(v4.hosts()),
            Cidr::V6(v6) => Hosts::V6(v6.hosts()),
        }
    }

    /// Returns the number of bits in the CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4([192, 168, 0, 1].into()), 24).unwrap();
    /// assert_eq!(ipv4_cidr.bits(), 24);
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()), 64).unwrap();
    /// assert_eq!(ipv6_cidr.bits(), 64);
    /// ```
    #[inline]
    pub const fn bits(&self) -> u8 {
        match self {
            Cidr::V4(v4) => v4.bits(),
            Cidr::V6(v6) => v6.bits(),
        }
    }

    /// Returns [`true`] if the CIDR block contains the given IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4([192, 168, 0, 1].into()), 24).unwrap();
    /// assert!(ipv4_cidr.contains(IpAddr::V4([192, 168, 0, 100].into())));
    /// assert!(!ipv4_cidr.contains(IpAddr::V4([192, 168, 1, 1].into())));
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()), 64).unwrap();
    /// assert!(ipv6_cidr.contains(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2].into())));
    /// assert!(!ipv6_cidr.contains(IpAddr::V6([0x2001, 0xdb9, 0, 0, 0, 0, 0, 1].into())));
    /// ```
    #[inline]
    pub const fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Cidr::V4(lh), IpAddr::V4(rh)) => lh.contains(rh),
            (Cidr::V6(lh), IpAddr::V6(rh)) => lh.contains(rh),
            _ => false,
        }
    }

    /// Returns [`true`] if the CIDR block contains the given CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr1 = Cidr::new(IpAddr::V4([192, 168, 1, 0].into()), 24).unwrap();
    /// let ipv4_cidr2 = Cidr::new(IpAddr::V4([192, 168, 0, 0].into()), 16).unwrap();
    ///
    /// let ipv6_cidr1 = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0].into()), 48).unwrap();
    /// let ipv6_cidr2 = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0].into()), 32).unwrap();
    ///
    /// assert!(!ipv4_cidr1.contains_cidr(&ipv4_cidr2));
    /// assert!(ipv4_cidr2.contains_cidr(&ipv4_cidr1));
    ///
    /// assert!(!ipv6_cidr1.contains_cidr(&ipv6_cidr2));
    /// assert!(ipv6_cidr2.contains_cidr(&ipv6_cidr1));
    ///
    /// assert!(!ipv4_cidr1.contains_cidr(&ipv6_cidr1));
    /// assert!(!ipv6_cidr1.contains_cidr(&ipv4_cidr1));
    /// ```
    #[inline]
    pub const fn contains_cidr(&self, other: &Cidr) -> bool {
        match (self, other) {
            (Cidr::V4(lh), Cidr::V4(rh)) => lh.contains_cidr(rh),
            (Cidr::V6(lh), Cidr::V6(rh)) => lh.contains_cidr(rh),
            _ => false,
        }
    }

    /// Returns [`true`] if the CIDR block overlaps with the given CIDR block.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let cidr1 = Cidr::new(IpAddr::V4([192, 168, 0, 0].into()), 24).unwrap();
    /// let cidr2 = Cidr::new(IpAddr::V4([192, 168, 1, 0].into()), 24).unwrap();
    /// let cidr3 = Cidr::new(IpAddr::V4([192, 168, 0, 0].into()), 16).unwrap();
    ///
    /// assert!(!cidr1.overlaps(&cidr2));
    /// assert!(cidr1.overlaps(&cidr3));
    /// assert!(cidr2.overlaps(&cidr3));
    ///
    /// let cidr4 = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0].into()), 48).unwrap();
    /// let cidr5 = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0].into()), 48).unwrap();
    /// let cidr6 = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0].into()), 32).unwrap();
    ///
    /// assert!(!cidr4.overlaps(&cidr5));
    /// assert!(cidr4.overlaps(&cidr6));
    /// assert!(cidr5.overlaps(&cidr6));
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4([192, 168, 0, 1].into()), 24).unwrap();
    /// assert!(ipv4_cidr.is_ipv4());
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()), 64).unwrap();
    /// assert!(!ipv6_cidr.is_ipv4());
    /// ```
    #[inline]
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, Cidr::V4(_))
    }

    /// Returns [`true`] if the CIDR block is an [`IPv6` CIDR block], and [`false`] otherwise.
    ///
    /// [`IPv6` CIDR block]: Cidr::V6
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::IpAddr;
    /// use cidrs::Cidr;
    ///
    /// let ipv6_cidr = Cidr::new(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()), 64).unwrap();
    /// assert!(ipv6_cidr.is_ipv6());
    ///
    /// let ipv4_cidr = Cidr::new(IpAddr::V4([192, 168, 0, 1].into()), 24).unwrap();
    /// assert!(!ipv4_cidr.is_ipv6());
    /// ```
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

pub enum Hosts {
    V4(Ipv4Hosts),
    V6(Ipv6Hosts),
}

impl Iterator for Hosts {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::V4(v4) => v4.next().map(IpAddr::V4),
            Self::V6(v6) => v6.next().map(IpAddr::V6),
        }
    }
}
