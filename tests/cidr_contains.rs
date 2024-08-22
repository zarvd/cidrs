use core::net::{Ipv4Addr, Ipv6Addr};

use cidrs::{Ipv4Cidr, Ipv6Cidr};
#[test]
fn ipv4_basic() {
    let cidr = Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap();

    // Test addresses within the CIDR block
    assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 1)));
    assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 254)));

    // Test the network address and broadcast address
    assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 0)));
    assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 255)));

    // Test addresses outside the CIDR block
    assert!(!cidr.contains(Ipv4Addr::new(192, 168, 1, 0)));
    assert!(!cidr.contains(Ipv4Addr::new(192, 167, 255, 255)));
}

#[test]
fn ipv6_basic() {
    let cidr = Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap();

    // Test addresses within the CIDR block
    assert!(cidr.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)));
    assert!(cidr.contains(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
    )));

    // Test the network address
    assert!(cidr.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));

    // Test addresses outside the CIDR block
    assert!(!cidr.contains(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0)));
    assert!(!cidr.contains(Ipv6Addr::new(
        0x2001, 0xdb7, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
    )));
}
