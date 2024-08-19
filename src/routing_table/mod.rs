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
    /// assert_eq!(table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42), None);
    /// assert_eq!(table.insert(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(), 42), Some(42));
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
    /// assert_eq!(table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()), Some(42));
    /// assert_eq!(table.remove(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()), None);
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
    /// assert_eq!(table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()), Some(&42));
    /// assert_eq!(table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap()), None);
    /// assert_eq!(table.match_exact(Ipv4Cidr::new([192, 168, 0, 0], 25).unwrap()), None);
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
    /// assert_eq!(table.match_longest(Ipv4Addr::new(192, 0, 0, 0)), None);
    /// assert_eq!(table.match_longest(Ipv4Addr::new(192, 168, 1, 1)), Some((Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), &2)));
    /// assert_eq!(table.match_longest(Ipv4Addr::new(192, 168, 2, 1)), Some((Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), &3)));
    /// assert_eq!(table.match_longest(Ipv4Addr::new(192, 168, 3, 1)), Some((Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1)));
    /// ```
    #[inline]
    pub fn match_longest(&self, addr: Ipv4Addr) -> Option<(Ipv4Cidr, &V)> {
        self.bitmap.match_longest(addr)
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
    /// assert_eq!(table.list_matched(Ipv4Addr::new(192, 0, 0, 0)), vec![]);
    /// assert_eq!(
    ///     table.list_matched(Ipv4Addr::new(192, 168, 1, 1)),
    ///     vec![
    ///         (Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1),
    ///         (Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), &2),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched(Ipv4Addr::new(192, 168, 2, 1)),
    ///     vec![
    ///         (Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1),
    ///         (Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(), &3),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched(Ipv4Addr::new(192, 168, 3, 1)),
    ///     vec![(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1)]
    /// );
    /// ```
    #[inline]
    pub fn list_matched(&self, addr: Ipv4Addr) -> Vec<(Ipv4Cidr, &V)> {
        self.bitmap.list_matched(addr)
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
    /// assert_eq!(table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42), None);
    /// assert_eq!(table.insert(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), 42), Some(42));
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
    /// assert_eq!(table.remove(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()), Some(42));
    /// assert_eq!(table.remove(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()), None);
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
    /// assert_eq!(table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()), Some(&42));
    /// assert_eq!(table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 63).unwrap()), None);
    /// assert_eq!(table.match_exact(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 65).unwrap()), None);
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
    /// assert_eq!(table.match_longest(Ipv6Addr::new(0, 0, 0, 1, 0, 0, 0, 0)), None);
    /// assert_eq!(table.match_longest(Ipv6Addr::new(0, 0, 0, 0, 0xbb, 0, 0, 0)), Some((Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1)));
    /// assert_eq!(table.match_longest(Ipv6Addr::new(0, 0, 0, 0, 0xff, 0, 0, 1)), Some((Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), &2)));
    /// assert_eq!(table.match_longest(Ipv6Addr::new(0, 0, 0, 0, 0xf1, 0, 0, 1)), Some((Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), &3)));
    /// ```
    #[inline]
    pub fn match_longest(&self, addr: Ipv6Addr) -> Option<(Ipv6Cidr, &V)> {
        self.bitmap.match_longest(addr)
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
    /// assert_eq!(table.list_matched(Ipv6Addr::new(0, 0, 0, 1, 0, 0, 0, 0)), vec![]);
    /// assert_eq!(
    ///     table.list_matched(Ipv6Addr::new(0, 0, 0, 0, 0xbb, 0, 0, 0)),
    ///     vec![(Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1)]
    /// );
    /// assert_eq!(
    ///     table.list_matched(Ipv6Addr::new(0, 0, 0, 0, 0xff, 0, 0, 1)),
    ///     vec![
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1),
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0xff, 0, 0, 0], 80).unwrap(), &2),
    ///     ]
    /// );
    /// assert_eq!(
    ///     table.list_matched(Ipv6Addr::new(0, 0, 0, 0, 0xf1, 0, 0, 1)),
    ///     vec![
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0], 64).unwrap(), &1),
    ///         (Ipv6Cidr::new([0, 0, 0, 0, 0xf1, 0, 0, 0], 80).unwrap(), &3),
    ///     ]
    /// );
    #[inline]
    pub fn list_matched(&self, addr: Ipv6Addr) -> Vec<(Ipv6Cidr, &V)> {
        self.bitmap.list_matched(addr)
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
///
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
    #[inline]
    pub fn new() -> Self {
        Self {
            v4: Ipv4CidrRoutingTable::new(),
            v6: Ipv6CidrRoutingTable::new(),
        }
    }

    #[inline]
    pub fn insert(&mut self, cidr: Cidr, value: V) -> Option<V> {
        match cidr {
            Cidr::V4(v4) => self.v4.insert(v4, value),
            Cidr::V6(v6) => self.v6.insert(v6, value),
        }
    }

    #[inline]
    pub fn remove(&mut self, cidr: Cidr) -> Option<V> {
        match cidr {
            Cidr::V4(v4) => self.v4.remove(v4),
            Cidr::V6(v6) => self.v6.remove(v6),
        }
    }

    #[inline]
    pub fn match_exact(&self, cidr: Cidr) -> Option<&V> {
        match cidr {
            Cidr::V4(v4) => self.v4.match_exact(v4),
            Cidr::V6(v6) => self.v6.match_exact(v6),
        }
    }

    #[inline]
    pub fn match_longest(&self, addr: IpAddr) -> Option<(Cidr, &V)> {
        match addr {
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

    #[inline]
    pub fn list_matched(&self, addr: IpAddr) -> Vec<(Cidr, &V)> {
        match addr {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_insert() {
        let mut table = Ipv4CidrRoutingTable::new();
        let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();
        assert_eq!(table.insert(cidr, 42), None);
        assert_eq!(table.insert(cidr, 42), Some(42));

        let cidr = Ipv4Cidr::new([192, 168, 0, 0], 25).unwrap();
        assert_eq!(table.insert(cidr, 41), None);
    }

    #[test]
    fn test_ipv4_longest_match() {
        let table = {
            let mut m = Ipv4CidrRoutingTable::new();

            let cidr = Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap();
            m.insert(cidr, cidr.to_string());

            for i1 in 1..128 {
                let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 6).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 7).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 8).unwrap();
                m.insert(cidr, cidr.to_string());

                for i2 in 0..128 {
                    let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 9).unwrap();
                    m.insert(cidr, cidr.to_string());
                    let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 11).unwrap();
                    m.insert(cidr, cidr.to_string());
                    let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 13).unwrap();
                    m.insert(cidr, cidr.to_string());
                    for i3 in 0..128 {
                        let cidr = Ipv4Cidr::new([i1, i2, i3, 0], 24).unwrap();
                        m.insert(cidr, cidr.to_string());
                    }
                }
            }

            m
        };
        let actual = table
            .match_longest(Ipv4Addr::new(1, 2, 3, 4))
            .map(|(k, v)| (k, v.clone()));
        let expected = {
            let cidr = Ipv4Cidr::new([1, 2, 3, 0], 24).unwrap();
            Some((cidr, cidr.to_string()))
        };

        assert_eq!(actual, expected);
    }
}
