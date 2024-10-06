use crate::{Cidr, Ipv4Cidr, Ipv6Cidr};

/// Partitions a slice of `Cidr` into separate vectors of `Ipv4Cidr` and `Ipv6Cidr`.
///
/// This function takes a slice of `Cidr` and separates them into two vectors:
/// one for IPv4 CIDRs and another for IPv6 CIDRs.
///
/// # Examples
///
/// ```
/// use cidrs::{Cidr, Ipv4Cidr, Ipv6Cidr, partition_by_ip_family};
///
/// let cidrs = vec![
///     Cidr::V4("192.168.0.0/24".parse().unwrap()),
///     Cidr::V6("2001:db8::/32".parse().unwrap()),
///     Cidr::V4("10.0.0.0/8".parse().unwrap()),
/// ];
///
/// let (ipv4_cidrs, ipv6_cidrs) = partition_by_ip_family(&cidrs);
///
/// assert_eq!(ipv4_cidrs.len(), 2);
/// assert_eq!(ipv6_cidrs.len(), 1);
/// assert_eq!(ipv4_cidrs[0], "192.168.0.0/24".parse::<Ipv4Cidr>().unwrap());
/// assert_eq!(ipv4_cidrs[1], "10.0.0.0/8".parse::<Ipv4Cidr>().unwrap());
/// assert_eq!(ipv6_cidrs[0], "2001:db8::/32".parse::<Ipv6Cidr>().unwrap());
/// ```
#[inline]
pub fn partition_by_ip_family(cidrs: &[Cidr]) -> (Vec<Ipv4Cidr>, Vec<Ipv6Cidr>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());

    for cidr in cidrs {
        match cidr {
            Cidr::V4(v) => v4.push(*v),
            Cidr::V6(v) => v6.push(*v),
        }
    }
    (v4, v6)
}

/// Aggregates a list of CIDR ranges into a minimal set of non-overlapping ranges.
///
/// This function takes a slice of `Cidr` (which can be either IPv4 or IPv6) and returns
/// a new `Vec<Cidr>` containing the aggregated ranges.
///
/// # Examples
///
/// ```
/// use cidrs::{Cidr, aggregate};
///
/// let cidrs = vec![
///     "192.168.0.0/24".parse().unwrap(),
///     "192.168.1.0/24".parse().unwrap(),
///     "10.0.0.0/8".parse().unwrap(),
///     "2001:db8::/32".parse().unwrap(),
///     "2001:db8:1::/48".parse().unwrap(),
/// ];
///
/// let aggregated = aggregate(&cidrs);
/// let expected: Vec<Cidr> = vec![
///     "10.0.0.0/8".parse().unwrap(),
///     "192.168.0.0/23".parse().unwrap(),
///     "2001:db8::/32".parse().unwrap(),
/// ];
/// assert_eq!(aggregated, expected);
/// ```
#[inline]
pub fn aggregate(cidrs: &[Cidr]) -> Vec<Cidr> {
    let (v4, v6) = partition_by_ip_family(cidrs);

    let v4 = aggregate_ipv4(&v4).into_iter().map(Cidr::V4);
    let v6 = aggregate_ipv6(&v6).into_iter().map(Cidr::V6);

    v4.chain(v6).collect()
}

const fn set_bit_at<const N: usize>(mut bytes: [u8; N], i: usize) -> [u8; N] {
    bytes[i / 8] |= 1 << (7 - (i % 8));
    bytes
}

const fn bit_at<const N: usize>(bytes: [u8; N], i: usize) -> u8 {
    bytes[i / 8] >> (7 - i % 8) & 1
}

fn is_adjacent<const N: usize>(b1: [u8; N], b2: [u8; N], i: usize) -> bool {
    if bit_at(b1, i - 1) == 0 {
        b2 == set_bit_at(b1, i - 1)
    } else {
        b1 == set_bit_at(b2, i - 1)
    }
}

fn merge_adjacent_ipv4(p1: Ipv4Cidr, p2: Ipv4Cidr) -> Option<Ipv4Cidr> {
    if p1.bits() != p2.bits() || p1.bits() == 0 {
        return None;
    }
    let bits = p1.bits();
    let p1_bytes = p1.network_addr().octets();
    let p2_bytes = p2.network_addr().octets();

    if is_adjacent(p1_bytes, p2_bytes, bits as usize) {
        Some((p1_bytes, bits - 1).try_into().unwrap())
    } else {
        None
    }
}

fn merge_adjacent_ipv6(p1: Ipv6Cidr, p2: Ipv6Cidr) -> Option<Ipv6Cidr> {
    if p1.bits() != p2.bits() || p1.bits() == 0 {
        return None;
    }
    let bits = p1.bits();
    let p1_bytes = p1.network_addr().octets();
    let p2_bytes = p2.network_addr().octets();

    if is_adjacent(p1_bytes, p2_bytes, bits as usize) {
        Some((p1_bytes, bits - 1).try_into().unwrap())
    } else {
        None
    }
}

/// Aggregates a list of IPv4 CIDR ranges into a minimal set of non-overlapping ranges.
///
/// # Examples
///
/// ```
/// use cidrs::{Ipv4Cidr, aggregate_ipv4};
///
/// let cidrs = vec![
///     "192.168.0.0/24".parse().unwrap(),
///     "192.168.1.0/24".parse().unwrap(),
///     "10.0.0.0/8".parse().unwrap(),
/// ];
///
/// let aggregated = aggregate_ipv4(&cidrs);
/// assert_eq!(aggregated.len(), 2);
/// assert!(aggregated.contains(&"192.168.0.0/23".parse().unwrap()));
/// assert!(aggregated.contains(&"10.0.0.0/8".parse().unwrap()));
/// ```
pub fn aggregate_ipv4(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    if cidrs.len() <= 1 {
        return cidrs.to_vec();
    }

    let mut cidrs = cidrs.to_vec();
    cidrs.sort_by_key(|v| v.network_addr());

    let mut rv = vec![cidrs[0]];

    for cidr in cidrs.into_iter().skip(1) {
        if rv[rv.len() - 1].contains_cidr(&cidr) {
            continue;
        }
        rv.push(cidr);

        while rv.len() >= 2 {
            let p1 = rv[rv.len() - 1];
            let p2 = rv[rv.len() - 2];
            match merge_adjacent_ipv4(p1, p2) {
                Some(p) => {
                    rv.pop().unwrap();
                    rv.pop().unwrap();
                    rv.push(p);
                }
                None => break,
            }
        }
    }

    rv
}

/// Aggregates a list of IPv6 CIDR ranges into a minimal set of non-overlapping ranges.
///
/// # Examples
///
/// ```
/// use cidrs::{Ipv6Cidr, aggregate_ipv6};
///
/// let cidrs = vec![
///     "2001:db8::/32".parse().unwrap(),
///     "2001:db8:1::/48".parse().unwrap(),
///     "2001:db8:2::/48".parse().unwrap(),
/// ];
///
/// let aggregated = aggregate_ipv6(&cidrs);
/// assert_eq!(aggregated.len(), 1);
/// assert!(aggregated.contains(&"2001:db8::/32".parse().unwrap()));
/// ```
pub fn aggregate_ipv6(cidrs: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    if cidrs.len() <= 1 {
        return cidrs.to_vec();
    }

    let mut cidrs = cidrs.to_vec();
    cidrs.sort_by_key(|v| v.network_addr());

    let mut rv = vec![cidrs[0]];

    for cidr in cidrs.into_iter().skip(1) {
        if rv[rv.len() - 1].contains_cidr(&cidr) {
            continue;
        }
        rv.push(cidr);

        while rv.len() >= 2 {
            let p1 = rv[rv.len() - 1];
            let p2 = rv[rv.len() - 2];
            match merge_adjacent_ipv6(p1, p2) {
                Some(p) => {
                    rv.pop().unwrap();
                    rv.pop().unwrap();
                    rv.push(p);
                }
                None => break,
            }
        }
    }

    rv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_bit_at() {
        assert_eq!(set_bit_at([0x00, 0x00], 0), [0b1000_0000, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 1), [0b0100_0000, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 2), [0b0010_0000, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 3), [0b0001_0000, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 4), [0b0000_1000, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 5), [0b0000_0100, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 6), [0b0000_0010, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 7), [0b0000_0001, 0x00]);
        assert_eq!(set_bit_at([0x00, 0x00], 8), [0x00, 0b1000_0000]);
        assert_eq!(set_bit_at([0x00, 0x00], 9), [0x00, 0b0100_0000]);
        assert_eq!(set_bit_at([0x00, 0x00], 10), [0x00, 0b0010_0000]);
        assert_eq!(set_bit_at([0x00, 0x00], 11), [0x00, 0b0001_0000]);
        assert_eq!(set_bit_at([0x00, 0x00], 12), [0x00, 0b0000_1000]);
        assert_eq!(set_bit_at([0x00, 0x00], 13), [0x00, 0b0000_0100]);
        assert_eq!(set_bit_at([0x00, 0x00], 14), [0x00, 0b0000_0010]);
        assert_eq!(set_bit_at([0x00, 0x00], 15), [0x00, 0b0000_0001]);
    }

    #[test]
    fn test_bit_at() {
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 0), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 1), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 2), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 3), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 4), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 5), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 6), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 7), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 8), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 9), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 10), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 11), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 12), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 13), 0);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 14), 1);
        assert_eq!(bit_at([0b0101_0101, 0b1010_1010], 15), 0);
    }

    #[test]
    fn test_is_adjacent() {
        assert!(is_adjacent([0b1010_1010], [0b1010_1011], 8));
        assert!(is_adjacent([0b1010_1011], [0b1010_1010], 8));

        assert!(is_adjacent(
            [0b1010_1010, 0b1000_0000],
            [0b1010_1010, 0x00],
            9
        ));

        assert!(!is_adjacent([0b1010_1010], [0b1010_1010], 8));
        assert!(!is_adjacent([0b1010_1001], [0b1010_1010], 8));
        assert!(!is_adjacent([0b1010_1000], [0b1010_1010], 8));
    }
}
