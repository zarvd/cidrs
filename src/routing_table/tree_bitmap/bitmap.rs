use core::ptr::NonNull;

use super::node::Node;
use super::{Nibble, Nibbles};

/// A tree bitmap implementation.
///
/// This is a tree bitmap implementation that is used to store and query CIDR ranges.
pub(crate) struct TreeBitmap<const N: usize, K, V>
where
    K: Copy + Into<Nibbles<N>>,
{
    root: NonNull<Node<(K, V)>>,
}

impl<const N: usize, K, V> TreeBitmap<N, K, V>
where
    K: Copy + Into<Nibbles<N>>,
{
    /// Creates a new tree bitmap.
    pub fn new() -> Self {
        let root = Node::internal();
        Self { root }
    }

    pub fn list_matched<I>(&self, key: I) -> Vec<(K, &V)>
    where
        I: Into<Nibbles<N>>,
    {
        let mut node = self.root;
        let mut rv = Vec::new();
        let mut is_end = false;
        for nibble in key.into() {
            let p = unsafe { node.as_ref() };
            rv.extend(p.list_values(nibble));
            if nibble.bits < 4 || p.is_end() {
                is_end = true;
                break;
            }
            node = if let Some(next) = p.get_child(nibble.byte) {
                next
            } else {
                is_end = true;
                break;
            };
        }
        if !is_end {
            if let Some(v) = unsafe { node.as_ref() }.get_longest_match_value(Nibble::nil()) {
                rv.push(v);
            }
        }

        rv.into_iter().map(|(k, v)| (*k, v)).collect()
    }

    pub fn match_exact<I>(&self, key: I) -> Option<&V>
    where
        I: Into<Nibbles<N>>,
    {
        let mut node = self.root;
        for nibble in key.into() {
            let p = unsafe { node.as_ref() };

            if nibble.bits < 4 || p.is_end() {
                return p.get_exact_match_value(nibble).map(|(_, v)| v);
            }
            node = p.get_child(nibble.byte)?;
        }
        let p = unsafe { node.as_ref() };

        p.get_exact_match_value(Nibble::nil()).map(|(_, v)| v)
    }

    pub fn match_longest<I>(&self, key: I) -> Option<(K, &V)>
    where
        I: Into<Nibbles<N>>,
    {
        let mut node = self.root;
        let mut rv = None;
        for nibble in key.into() {
            let p = unsafe { node.as_ref() };

            if let Some((k, v)) = p.get_longest_match_value(nibble) {
                rv = Some((k, v));
            }

            if nibble.bits < 4 || p.is_end() {
                break;
            }
            node = if let Some(next) = p.get_child(nibble.byte) {
                next
            } else {
                break;
            };
        }
        if let Some((k, v)) = unsafe { node.as_ref() }.get_longest_match_value(Nibble::nil()) {
            rv = Some((k, v));
        }

        rv.into_iter().map(|(k, v)| (*k, v)).next()
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let mut node = self.root;
        for (i, nibble) in key.into().enumerate() {
            let p = unsafe { node.as_mut() };

            if nibble.bits < 4 || p.is_end() {
                let rv = p.remove_value(nibble).map(|(_, v)| v);
                p.set_value(nibble, (key, value));
                return rv;
            }

            if let Some(next) = p.get_child(nibble.byte) {
                node = next;
                continue;
            }
            // create new node
            let next = if (i + 1) * 4 == N * 8 {
                Node::end()
            } else {
                Node::internal()
            };
            node = next;
            p.set_child(nibble.byte, next);
        }

        let p = unsafe { node.as_mut() };
        let rv = p.remove_value(Nibble::nil()).map(|(_, v)| v);
        p.set_value(Nibble::nil(), (key, value));
        rv
    }

    pub fn remove(&mut self, key: K) -> Option<V> {
        let mut node = self.root;
        for nibble in key.into() {
            let p = unsafe { node.as_mut() };

            if nibble.bits < 4 || p.is_end() {
                return p.remove_value(nibble).map(|(_, v)| v);
            }

            if let Some(next) = p.get_child(nibble.byte) {
                node = next;
            } else {
                return None;
            }
        }
        let p = unsafe { node.as_mut() };
        p.remove_value(Nibble::nil()).map(|(_, v)| v)
    }
}

impl<const N: usize, K, V> Drop for TreeBitmap<N, K, V>
where
    K: Copy + Into<Nibbles<N>>,
{
    fn drop(&mut self) {
        unsafe {
            let _ = Box::from_raw(self.root.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
    use crate::Ipv4Cidr;

    fn parse_ipv4_cidrs(cidrs: &[&str]) -> Vec<Ipv4Cidr> {
        cidrs.iter().map(|v| v.parse().unwrap()).collect()
    }

    #[test]
    fn test_ipv4_tree_bitmap_match_exact() {
        let tests = [
            "192.168.0.1/32",
            "192.168.0.0/16",
            "192.168.3.0/24",
            "0.0.0.0/0",
        ];

        for ip in tests {
            let mut map = TreeBitmap::new();

            let k = ip.parse::<Ipv4Cidr>().unwrap();
            let v = ip.to_owned();
            assert!(map.insert(k, v.clone()).is_none());
            assert_eq!(map.match_exact(k), Some(&v));
        }
    }

    #[test]
    fn test_ipv4_tree_bitmap_list_matched() {
        let mut map = TreeBitmap::new();
        let cidrs = parse_ipv4_cidrs(&[
            "192.168.122.1/32",
            "192.168.122.0/31",
            "192.168.122.0/30",
            "192.168.122.0/24",
            "192.168.122.0/23",
            "192.168.121.0/24",
            "192.168.122.2/32",
            "192.168.0.0/16",
            "192.167.0.0/16",
            "10.0.0.1/32",
            "10.0.0.0/8",
            "0.0.0.0/0",
        ]);

        for k in cidrs {
            assert_eq!(map.insert(k, k.to_string()), None, "inserting {k}");
        }

        let tests = [
            (
                [192, 168, 122, 1],
                vec![
                    "0.0.0.0/0",
                    "192.168.0.0/16",
                    "192.168.122.0/23",
                    "192.168.122.0/24",
                    "192.168.122.0/30",
                    "192.168.122.0/31",
                    "192.168.122.1/32",
                ],
            ),
            (
                [10, 0, 0, 1],
                vec!["0.0.0.0/0", "10.0.0.0/8", "10.0.0.1/32"],
            ),
        ];

        for (key, expected) in tests {
            let k = Ipv4Addr::from(key);
            let actual = map
                .list_matched(k)
                .into_iter()
                .map(|(k, v)| (k, v.clone()))
                .collect::<Vec<_>>();

            let expected = parse_ipv4_cidrs(&expected)
                .into_iter()
                .map(|k| (k, k.to_string()))
                .collect::<Vec<_>>();

            assert_eq!(actual, expected);
        }
    }
}
