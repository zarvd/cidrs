pub(crate) mod tree_bitmap;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tree_bitmap::{Nibble, TreeBitmap};

pub use crate::cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};

macro_rules! cidr_routing_table {
    ($name:ident, $cidr:ty, $addr:ty) => {
        pub struct $name<V> {
            bitmap: TreeBitmap<$cidr, V>,
        }

        impl<V> Default for $name<V> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<V> $name<V> {
            #[inline(always)]
            pub fn new() -> Self {
                Self {
                    bitmap: TreeBitmap::new(<$cidr>::MAX_BITS as usize),
                }
            }

            #[inline(always)]
            pub fn insert(&mut self, cidr: $cidr, value: V) -> Option<V> {
                self.bitmap.insert(cidr, value)
            }

            #[inline(always)]
            pub fn remove(&mut self, cidr: $cidr) -> Option<V> {
                self.bitmap.remove(cidr)
            }

            #[inline(always)]
            pub fn match_longest(&self, addr: &$addr) -> Option<(&$cidr, &V)> {
                let nibbles = Nibble::from_octets(&addr.octets(), <$cidr>::MAX_BITS);
                self.bitmap.match_longest(&nibbles)
            }

            #[inline(always)]
            pub fn match_exact(&self, cidr: &$cidr) -> Option<&V> {
                self.bitmap.match_exact(cidr)
            }

            #[inline(always)]
            pub fn list_matched(&self, addr: &$addr) -> Vec<(&$cidr, &V)> {
                let nibbles = Nibble::from_octets(&addr.octets(), <$cidr>::MAX_BITS);
                self.bitmap.list_matched(&nibbles)
            }
        }
    };
}

cidr_routing_table!(Ipv4CidrRoutingTable, Ipv4Cidr, Ipv4Addr);
cidr_routing_table!(Ipv6CidrRoutingTable, Ipv6Cidr, Ipv6Addr);

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
    pub fn new() -> Self {
        Self {
            v4: Ipv4CidrRoutingTable::new(),
            v6: Ipv6CidrRoutingTable::new(),
        }
    }

    pub fn insert(&mut self, cidr: Cidr, value: V) -> Option<V> {
        match cidr {
            Cidr::V4(v4) => self.v4.insert(v4, value),
            Cidr::V6(v6) => self.v6.insert(v6, value),
        }
    }

    pub fn remove(&mut self, cidr: Cidr) -> Option<V> {
        match cidr {
            Cidr::V4(v4) => self.v4.remove(v4),
            Cidr::V6(v6) => self.v6.remove(v6),
        }
    }

    pub fn match_longest(&self, addr: &IpAddr) -> Option<(Cidr, &V)> {
        match addr {
            IpAddr::V4(v4) => self
                .v4
                .match_longest(v4)
                .map(|(cidr, v)| (Cidr::V4(*cidr), v)),
            IpAddr::V6(v6) => self
                .v6
                .match_longest(v6)
                .map(|(cidr, v)| (Cidr::V6(*cidr), v)),
        }
    }

    pub fn match_exact(&self, cidr: &Cidr) -> Option<&V> {
        match cidr {
            Cidr::V4(v4) => self.v4.match_exact(v4),
            Cidr::V6(v6) => self.v6.match_exact(v6),
        }
    }

    pub fn list_matched(&self, addr: &IpAddr) -> Vec<(Cidr, &V)> {
        match addr {
            IpAddr::V4(v4) => self
                .v4
                .list_matched(v4)
                .into_iter()
                .map(|(cidr, v)| (Cidr::V4(*cidr), v))
                .collect(),
            IpAddr::V6(v6) => self
                .v6
                .list_matched(v6)
                .into_iter()
                .map(|(cidr, v)| (Cidr::V6(*cidr), v))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_longest_match() {
        let table = {
            let mut m = Ipv4CidrRoutingTable::new();

            let cidr = Ipv4Cidr::new(0, 0, 0, 0, 0).unwrap();
            m.insert(cidr, cidr.to_string());

            for i1 in 1..128 {
                let cidr = Ipv4Cidr::new(i1, 0, 0, 0, 6).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new(i1, 0, 0, 0, 7).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new(i1, 0, 0, 0, 8).unwrap();
                m.insert(cidr, cidr.to_string());

                for i2 in 0..128 {
                    let cidr = Ipv4Cidr::new(i1, i2, 0, 0, 9).unwrap();
                    m.insert(cidr, cidr.to_string());
                    let cidr = Ipv4Cidr::new(i1, i2, 0, 0, 11).unwrap();
                    m.insert(cidr, cidr.to_string());
                    let cidr = Ipv4Cidr::new(i1, i2, 0, 0, 13).unwrap();
                    m.insert(cidr, cidr.to_string());
                    for i3 in 0..128 {
                        let cidr = Ipv4Cidr::new(i1, i2, i3, 0, 24).unwrap();
                        m.insert(cidr, cidr.to_string());
                    }
                }
            }

            m
        };
        let actual = table
            .match_longest(&Ipv4Addr::new(1, 2, 3, 4))
            .map(|(k, v)| (*k, v.clone()));
        let expected = {
            let cidr = Ipv4Cidr::new(1, 2, 3, 0, 24).unwrap();
            Some((cidr, cidr.to_string()))
        };

        assert_eq!(actual, expected);
    }
}
