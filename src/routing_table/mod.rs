pub(crate) mod tree_bitmap;

pub use crate::cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tree_bitmap::TreeBitmap;

/// A routing table for IPv4 CIDRs.
pub struct Ipv4CidrRoutingTable<V> {
    bitmap: TreeBitmap<4, Ipv4Cidr, V>,
}

impl<V> Ipv4CidrRoutingTable<V> {
    /// Creates an empty `Ipv4CidrRoutingTable`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv4CidrRoutingTable;
    /// let table = Ipv4CidrRoutingTable::<String>::new();
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            bitmap: TreeBitmap::new(Ipv4Cidr::MAX_BITS as usize),
        }
    }

    /// Inserts a IPv4 CIDR and its value into the table.
    ///
    /// If the table did not have this IPv4 CIDR present, [`None`] is returned.
    ///
    /// If the table did have this IPv4 CIDR present, the value is updated, and the old value is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};
    ///
    /// let mut table = Ipv4CidrRoutingTable::<u64>::new();
    /// assert_eq!(
    ///     table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42),
    ///     Some(42)
    /// );
    /// ```
    #[inline]
    pub fn insert(&mut self, cidr: Ipv4Cidr, value: V) -> Option<V> {
        self.bitmap.insert(cidr, value)
    }

    /// Removes a IPv4 CIDR from the table, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};
    ///
    /// let mut table = Ipv4CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42);
    /// assert_eq!(
    ///     table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     Some(42)
    /// );
    /// assert_eq!(
    ///     table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn remove(&mut self, cidr: Ipv4Cidr) -> Option<V> {
        self.bitmap.remove(cidr)
    }

    /// Matches the exact IPv4 CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};
    ///
    /// let mut table = Ipv4CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42);
    /// assert_eq!(
    ///     table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     Some(&42)
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap()),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 25).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn match_exact(&self, cidr: Ipv4Cidr) -> Option<&V> {
        self.bitmap.match_exact(cidr)
    }

    /// Matches the longest IPv4 CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    ///
    /// use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};
    ///
    /// let mut table = Ipv4CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), 1);
    /// table.insert(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), 2);
    /// table.insert(Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), 3);
    ///
    /// assert_eq!(table.match_longest([192, 0, 0, 0]), None);
    /// assert_eq!(
    ///     table.match_longest([192, 168, 1, 1]),
    ///     Some((Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), &2))
    /// );
    /// assert_eq!(
    ///     table.match_longest([192, 168, 2, 1]),
    ///     Some((Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), &3))
    /// );
    /// assert_eq!(
    ///     table.match_longest([192, 168, 3, 1]),
    ///     Some((Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1))
    /// );
    /// ```
    #[inline]
    pub fn match_longest<I>(&self, addr: I) -> Option<(Ipv4Cidr, &V)>
    where
        I: Into<Ipv4Addr>,
    {
        self.bitmap.match_longest(addr.into())
    }

    /// List all matched IPv4 CIDRs and their values.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    ///
    /// use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};
    ///
    /// let mut table = Ipv4CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), 1);
    /// table.insert(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), 2);
    /// table.insert(Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), 3);
    ///
    /// assert_eq!(table.list_matched([192, 0, 0, 0]), vec![]);
    /// assert_eq!(
    ///     table.list_matched([192, 168, 1, 1]),
    ///     vec![
    ///         (Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1),
    ///         (Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), &2),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched([192, 168, 2, 1]),
    ///     vec![
    ///         (Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1),
    ///         (Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), &3),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched([192, 168, 3, 1]),
    ///     vec![(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1)]
    /// );
    /// ```
    #[inline]
    pub fn list_matched<I>(&self, addr: I) -> Vec<(Ipv4Cidr, &V)>
    where
        I: Into<Ipv4Addr>,
    {
        self.bitmap.list_matched(addr.into())
    }
}

impl<V> Default for Ipv4CidrRoutingTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A routing table for IPv6 CIDRs.
pub struct Ipv6CidrRoutingTable<V> {
    bitmap: TreeBitmap<16, Ipv6Cidr, V>,
}

impl<V> Ipv6CidrRoutingTable<V> {
    /// Creates an empty `Ipv6CidrRoutingTable`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::Ipv6CidrRoutingTable;
    /// let table = Ipv6CidrRoutingTable::<String>::new();
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            bitmap: TreeBitmap::new(Ipv6Cidr::MAX_BITS as usize),
        }
    }

    /// Inserts a IPv6 CIDR and its value into the table.
    ///
    /// If the table did not have this IPv6 CIDR present, [`None`] is returned.
    ///
    /// If the table did have this IPv6 CIDR present, the value is updated, and the old value is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv6Cidr, Ipv6CidrRoutingTable};
    ///
    /// let mut table = Ipv6CidrRoutingTable::<u64>::new();
    /// assert_eq!(
    ///     table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42),
    ///     Some(42)
    /// );
    /// ```
    #[inline]
    pub fn insert(&mut self, cidr: Ipv6Cidr, value: V) -> Option<V> {
        self.bitmap.insert(cidr, value)
    }

    /// Removes a IPv6 CIDR from the table, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv6Cidr, Ipv6CidrRoutingTable};
    ///
    /// let mut table = Ipv6CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42);
    /// assert_eq!(
    ///     table.remove(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///     Some(42)
    /// );
    /// assert_eq!(
    ///     table.remove(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn remove(&mut self, cidr: Ipv6Cidr) -> Option<V> {
        self.bitmap.remove(cidr)
    }

    /// Matches the exact IPv6 CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Ipv6Cidr, Ipv6CidrRoutingTable};
    ///
    /// let mut table = Ipv6CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42);
    /// assert_eq!(
    ///     table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///     Some(&42)
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 63).unwrap()),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 65).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn match_exact(&self, cidr: Ipv6Cidr) -> Option<&V> {
        self.bitmap.match_exact(cidr)
    }

    /// Matches the longest IPv6 CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    ///
    /// use cidrs::{Ipv6Cidr, Ipv6CidrRoutingTable};
    ///
    /// let mut table = Ipv6CidrRoutingTable::<u64>::new();
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 1);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), 2);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), 3);
    ///
    /// assert_eq!(table.match_longest([0, 0, 0, 1, 0, 0, 0, 0]), None);
    /// assert_eq!(
    ///     table.match_longest([0, 0, 0, 0, 0xbb, 0, 0, 0]),
    ///     Some((Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1))
    /// );
    /// assert_eq!(
    ///     table.match_longest([0, 0, 0, 0, 0xff, 0, 0, 1]),
    ///     Some((Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), &2))
    /// );
    /// assert_eq!(
    ///     table.match_longest([0, 0, 0, 0, 0xf1, 0, 0, 1]),
    ///     Some((Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), &3))
    /// );
    /// ```
    #[inline]
    pub fn match_longest<I>(&self, addr: I) -> Option<(Ipv6Cidr, &V)>
    where
        I: Into<Ipv6Addr>,
    {
        self.bitmap.match_longest(addr.into())
    }

    /// List all matched IPv6 CIDRs and their values.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    ///
    /// use cidrs::{Ipv6Cidr, Ipv6CidrRoutingTable};
    ///
    /// let mut table = Ipv6CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 1);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), 2);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), 3);
    ///
    /// assert_eq!(table.list_matched([0, 0, 0, 1, 0, 0, 0, 0]), vec![]);
    /// assert_eq!(
    ///     table.list_matched([0, 0, 0, 0, 0xbb, 0, 0, 0]),
    ///     vec![(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1)]
    /// );
    /// assert_eq!(
    ///     table.list_matched([0, 0, 0, 0, 0xff, 0, 0, 1]),
    ///     vec![
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1),
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), &2),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched([0, 0, 0, 0, 0xf1, 0, 0, 1]),
    ///     vec![
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1),
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), &3),
    ///     ]
    /// );
    #[inline]
    pub fn list_matched<I>(&self, addr: I) -> Vec<(Ipv6Cidr, &V)>
    where
        I: Into<Ipv6Addr>,
    {
        self.bitmap.list_matched(addr.into())
    }
}

impl<V> Default for Ipv6CidrRoutingTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A routing table for both IPv4 and IPv6 CIDRs.
///
/// This is a wrapper around [`Ipv4CidrRoutingTable`] and [`Ipv6CidrRoutingTable`].
pub struct CidrRoutingTable<V> {
    v4: Ipv4CidrRoutingTable<V>,
    v6: Ipv6CidrRoutingTable<V>,
}

impl<V> Default for CidrRoutingTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> CidrRoutingTable<V> {
    /// Creates an empty `CidrRoutingTable`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::CidrRoutingTable;
    ///
    /// let table = CidrRoutingTable::<String>::new();
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            v4: Ipv4CidrRoutingTable::new(),
            v6: Ipv6CidrRoutingTable::new(),
        }
    }

    /// Inserts a CIDR and its value into the table.
    ///
    /// If the table did not have this CIDR present, [`None`] is returned.
    ///
    /// If the table did have this CIDR present, the value is updated, and the old value is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr, Ipv6Cidr};
    ///
    /// let mut table = CidrRoutingTable::<u64>::new();
    ///
    /// assert_eq!(
    ///     table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 1),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 2),
    ///     Some(1)
    /// );
    ///
    /// assert_eq!(
    ///     table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 3),
    ///     None
    /// );
    /// assert_eq!(
    ///     table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 4),
    ///     Some(3)
    /// );
    /// ```
    #[inline]
    pub fn insert<I>(&mut self, cidr: I, value: V) -> Option<V>
    where
        I: Into<Cidr>,
    {
        match cidr.into() {
            Cidr::V4(v4) => self.v4.insert(v4, value),
            Cidr::V6(v6) => self.v6.insert(v6, value),
        }
    }

    /// Removes a CIDR from the table, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{CidrRoutingTable, Ipv4Cidr};
    ///
    /// let mut table = CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42);
    /// assert_eq!(
    ///     table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     Some(42)
    /// );
    /// assert_eq!(
    ///     table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn remove<I>(&mut self, cidr: I) -> Option<V>
    where
        I: Into<Cidr>,
    {
        match cidr.into() {
            Cidr::V4(v4) => self.v4.remove(v4),
            Cidr::V6(v6) => self.v6.remove(v6),
        }
    }

    /// Matches the exact CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr, Ipv6Cidr};
    ///
    /// let mut table = CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 1);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 2);
    /// assert_eq!(
    ///     table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()),
    ///     Some(&1)
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap()),
    ///     None
    /// );
    ///
    /// assert_eq!(
    ///     table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///     Some(&2)
    /// );
    /// assert_eq!(
    ///     table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 63).unwrap()),
    ///     None
    /// );
    /// ```
    #[inline]
    pub fn match_exact<I>(&self, cidr: I) -> Option<&V>
    where
        I: Into<Cidr>,
    {
        match cidr.into() {
            Cidr::V4(v4) => self.v4.match_exact(v4),
            Cidr::V6(v6) => self.v6.match_exact(v6),
        }
    }

    /// Matches the longest CIDR, returning the value at the key if the key was previously in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr, Ipv6Cidr};
    ///
    /// let mut table = CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), 1);
    /// table.insert(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), 2);
    ///
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 3);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), 4);
    ///
    /// assert_eq!(table.match_longest([192, 0, 0, 0]), None);
    /// assert_eq!(
    ///     table.match_longest([192, 168, 1, 1]),
    ///     Some((Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap()), &2))
    /// );
    /// assert_eq!(
    ///     table.match_longest([192, 168, 2, 1]),
    ///     Some((Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap()), &1))
    /// );
    ///
    /// assert_eq!(table.match_longest([0, 0, 0, 1, 0, 0, 0, 0]), None);
    /// assert_eq!(
    ///     table.match_longest([0, 0, 0, 0, 0xff, 0, 0, 1]),
    ///     Some((
    ///         Cidr::V6(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap()),
    ///         &4
    ///     ))
    /// );
    /// assert_eq!(
    ///     table.match_longest([0, 0, 0, 0, 0xf1, 0, 0, 1]),
    ///     Some((
    ///         Cidr::V6(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///         &3
    ///     ))
    /// );
    /// ```
    #[inline]
    pub fn match_longest<I>(&self, addr: I) -> Option<(Cidr, &V)>
    where
        I: Into<IpAddr>,
    {
        match addr.into() {
            IpAddr::V4(v4) => self
                .v4
                .match_longest(v4)
                .map(|(cidr, v)| (Cidr::V4(cidr), v)),
            IpAddr::V6(v6) => self
                .v6
                .match_longest(v6)
                .map(|(cidr, v)| (Cidr::V6(cidr), v)),
        }
    }

    /// List all matched CIDRs and their values.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr, Ipv6Cidr};
    ///
    /// let mut table = CidrRoutingTable::<u64>::new();
    ///
    /// table.insert(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), 1);
    /// table.insert(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), 2);
    ///
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 3);
    /// table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), 4);
    ///
    /// assert_eq!(table.list_matched([192, 0, 0, 0]), vec![]);
    /// assert_eq!(
    ///     table.list_matched([192, 168, 1, 1]),
    ///     vec![
    ///         (Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap()), &1),
    ///         (Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap()), &2),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched([192, 168, 2, 1]),
    ///     vec![(Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap()), &1)]
    /// );
    ///
    /// assert_eq!(table.list_matched([0, 0, 0, 1, 0, 0, 0, 0]), vec![]);
    /// assert_eq!(
    ///     table.list_matched(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0xff, 0, 0, 1))),
    ///     vec![
    ///         (
    ///             Cidr::V6(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()),
    ///             &3
    ///         ),
    ///         (
    ///             Cidr::V6(Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap()),
    ///             &4
    ///         ),
    ///     ]
    /// );
    /// ```
    #[inline]
    pub fn list_matched<I>(&self, addr: I) -> Vec<(Cidr, &V)>
    where
        I: Into<IpAddr>,
    {
        match addr.into() {
            IpAddr::V4(v4) => self
                .v4
                .list_matched(v4)
                .into_iter()
                .map(|(cidr, v)| (Cidr::V4(cidr), v))
                .collect(),
            IpAddr::V6(v6) => self
                .v6
                .list_matched(v6)
                .into_iter()
                .map(|(cidr, v)| (Cidr::V6(cidr), v))
                .collect(),
        }
    }
}
