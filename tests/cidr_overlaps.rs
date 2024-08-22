use cidrs::{Ipv4Cidr, Ipv6Cidr};

#[test]
fn ipv4_basic() {
    let tests = [
        // Identical networks
        (
            Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
            Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
            true,
        ),
        // One network contains the other
        (
            Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(),
            Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
            true,
        ),
        // Overlapping networks
        (
            Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap(),
            Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
            true,
        ),
        // Adjacent networks
        (
            Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
            Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
            false,
        ),
        // Completely separate networks
        (
            Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
            Ipv4Cidr::new([10, 0, 0, 0], 8).unwrap(),
            false,
        ),
    ];

    for (cidr1, cidr2, expected) in tests {
        assert_eq!(cidr1.overlaps(&cidr2), expected);
        assert_eq!(cidr2.overlaps(&cidr1), expected); // Test symmetry
    }
}

#[test]
fn ipv6_basic() {
    let tests = [
        // Identical networks
        (
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap(),
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap(),
            true,
        ),
        // One network contains the other
        (
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32).unwrap(),
            Ipv6Cidr::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0], 48).unwrap(),
            true,
        ),
        // Overlapping networks
        (
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 47).unwrap(),
            Ipv6Cidr::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0], 48).unwrap(),
            true,
        ),
        // Adjacent networks
        (
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap(),
            Ipv6Cidr::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0], 48).unwrap(),
            false,
        ),
        // Completely separate networks
        (
            Ipv6Cidr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 48).unwrap(),
            Ipv6Cidr::new([0x2002, 0, 0, 0, 0, 0, 0, 0], 16).unwrap(),
            false,
        ),
    ];

    for (cidr1, cidr2, expected) in tests {
        assert_eq!(cidr1.overlaps(&cidr2), expected);
        assert_eq!(cidr2.overlaps(&cidr1), expected); // Test symmetry
    }
}
