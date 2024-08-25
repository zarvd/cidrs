use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ptr::NonNull;

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

    let mut tree = Tree::<Ipv4Cidr>::new();
    let mut cidrs = cidrs.to_vec();
    cidrs.sort_unstable();
    for cidr in cidrs {
        tree.insert(cidr);
    }
    tree.list()
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

    let mut tree = Tree::<Ipv6Cidr>::new();
    let mut cidrs = cidrs.to_vec();
    cidrs.sort_unstable();
    for cidr in cidrs {
        tree.insert(cidr);
    }
    tree.list()
}

struct Node<T> {
    cidr: T,
    is_masked: bool,
    parent: Option<NonNull<Node<T>>>,
    left: Option<NonNull<Node<T>>>,
    right: Option<NonNull<Node<T>>>,
}

impl<T> Node<T> {
    #[inline]
    fn new(parent: Option<NonNull<Node<T>>>, cidr: T) -> NonNull<Self> {
        let boxed = Box::new(Self {
            parent,
            cidr,
            is_masked: false,
            left: None,
            right: None,
        });

        let ptr = Box::into_raw(boxed);
        NonNull::new(ptr).unwrap()
    }

    #[inline]
    fn get_or_new_left_child<F>(&mut self, f: F) -> NonNull<Self>
    where
        F: FnOnce() -> NonNull<Self>,
    {
        *self.left.get_or_insert_with(f)
    }

    #[inline]
    fn get_or_new_right_child<F>(&mut self, f: F) -> NonNull<Self>
    where
        F: FnOnce() -> NonNull<Self>,
    {
        *self.right.get_or_insert_with(f)
    }

    #[inline]
    fn clear_children(&mut self) {
        if let Some(left) = self.left.take() {
            let _ = unsafe { Box::from_raw(left.as_ptr()) };
        }
        if let Some(right) = self.right.take() {
            let _ = unsafe { Box::from_raw(right.as_ptr()) };
        }
    }
}

impl<T> Drop for Node<T> {
    fn drop(&mut self) {
        self.clear_children();
    }
}

struct Tree<T> {
    root: NonNull<Node<T>>,
}

impl<T> Drop for Tree<T> {
    fn drop(&mut self) {
        unsafe {
            let _ = Box::from_raw(self.root.as_ptr());
        }
    }
}

impl<T> Tree<T>
where
    T: Copy + fmt::Debug,
{
    fn pruning(node: NonNull<Node<T>>) {
        let mut parent = {
            let p = unsafe { node.as_ref() };
            p.parent
        };

        while let Some(mut node) = parent {
            let p = unsafe { node.as_mut() };
            let mut masked = 0;
            if let Some(left) = p.left {
                let l = unsafe { left.as_ref() };
                if l.is_masked {
                    masked += 1;
                }
            }
            if let Some(right) = p.right {
                let r = unsafe { right.as_ref() };
                if r.is_masked {
                    masked += 1;
                }
            }

            if masked < 2 {
                break;
            }
            p.is_masked = true;
            parent = p.parent;
        }
    }

    pub fn list(&self) -> Vec<T> {
        use std::collections::VecDeque;

        let mut rv = vec![];
        let mut q = VecDeque::new();

        q.push_back(self.root);

        while let Some(node) = q.pop_front() {
            let p = unsafe { node.as_ref() };
            if p.is_masked {
                rv.push(p.cidr);
                continue;
            }
            if let Some(left) = p.left {
                q.push_back(left);
            }
            if let Some(right) = p.right {
                q.push_back(right);
            }
        }
        rv
    }
}

impl Tree<Ipv4Cidr> {
    #[inline]
    pub fn new() -> Self {
        Self {
            root: Node::new(None, Ipv4Cidr::from_ip(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
        }
    }

    pub fn insert(&mut self, cidr: Ipv4Cidr) {
        let bytes = u32::from_be_bytes(cidr.octets());

        let mut node = self.root;
        for i in 0..cidr.bits() {
            let p = unsafe { node.as_mut() };

            if p.is_masked {
                break;
            }

            let bit = (bytes >> (31 - i)) & 1;
            let f = || Node::new(Some(node), Ipv4Cidr::new(cidr.octets(), i + 1).unwrap());
            node = if bit == 0 {
                p.get_or_new_left_child(f)
            } else {
                p.get_or_new_right_child(f)
            }
        }

        let p = unsafe { node.as_mut() };
        p.is_masked = true;
        p.clear_children();
        Self::pruning(node);
    }
}

impl Tree<Ipv6Cidr> {
    #[inline]
    pub fn new() -> Self {
        Self {
            root: Node::new(None, Ipv6Cidr::from_ip(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
        }
    }

    pub fn insert(&mut self, cidr: Ipv6Cidr) {
        let bytes = u128::from_be_bytes(cidr.octets());

        let mut node = self.root;
        for i in 0..cidr.bits() {
            let p = unsafe { node.as_mut() };
            if p.is_masked {
                break;
            }

            let bit = (bytes >> (31 - i)) & 1;
            let f = || {
                Node::new(
                    Some(node),
                    Ipv6Cidr::from_ip(cidr.network_addr(), i + 1).unwrap(),
                )
            };
            node = if bit == 0 {
                p.get_or_new_left_child(f)
            } else {
                p.get_or_new_right_child(f)
            }
        }

        let p = unsafe { node.as_mut() };
        p.is_masked = true;
        p.clear_children();
        Self::pruning(node);
    }
}
