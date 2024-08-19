use super::node::Node;
use super::{Nibble, TreeBitmap};
use crate::Ipv4Cidr;

mod dropped {
    use core::cell::RefCell;
    use std::rc::Rc;

    /// A helper struct to check if the value is dropped.
    #[derive(Clone)]
    pub struct Dropped {
        v: Rc<RefCell<bool>>,
    }

    impl Dropped {
        pub fn new() -> (Self, Value) {
            let me = Self {
                v: Rc::new(RefCell::new(false)),
            };

            (me.clone(), Value { dropped: me })
        }

        pub fn is_dropped(&self) -> bool {
            *self.v.borrow()
        }
    }

    pub struct Value {
        dropped: Dropped,
    }

    impl Drop for Value {
        fn drop(&mut self) {
            *self.dropped.v.borrow_mut() = true;
        }
    }
}

use dropped::Dropped;

#[test]
fn drop_node() {
    let mut p = Node::internal();
    let (d1, v1) = Dropped::new();
    unsafe { p.as_mut() }.set_value(Nibble::nil(), v1);

    let mut c = Node::internal();
    unsafe { p.as_mut() }.set_child(0b1000, c);
    let (d2, v2) = Dropped::new();
    unsafe { c.as_mut() }.set_value(Nibble::nil(), v2);

    assert!(!d1.is_dropped());
    assert!(!d2.is_dropped());
    unsafe {
        let _ = Box::from_raw(p.as_ptr());
    }
    assert!(d1.is_dropped());
    assert!(d2.is_dropped());
}

#[test]
fn drop_tree_bitmap() {
    let mut tree = TreeBitmap::new(32);
    let (d1, v1) = Dropped::new();
    tree.insert(Ipv4Cidr::new([1, 1, 1, 1], 32).unwrap(), v1);

    let (d2, v2) = Dropped::new();
    tree.insert(Ipv4Cidr::new([1, 1, 1, 1], 24).unwrap(), v2);

    let (d3, v3) = Dropped::new();
    tree.insert(Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap(), v3);

    assert!(!d1.is_dropped());
    assert!(!d2.is_dropped());
    assert!(!d3.is_dropped());

    let (d4, v4) = Dropped::new();
    tree.insert(Ipv4Cidr::new([1, 1, 1, 1], 24).unwrap(), v4);

    assert!(!d1.is_dropped());
    assert!(d2.is_dropped());
    assert!(!d3.is_dropped());
    assert!(!d4.is_dropped());

    drop(tree);

    assert!(d1.is_dropped());
    assert!(d2.is_dropped());
    assert!(d3.is_dropped());
    assert!(d4.is_dropped());
}
