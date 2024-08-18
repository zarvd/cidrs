use std::net::{IpAddr, Ipv4Addr};

use cidrs::{Cidr, Ipv4Cidr};

fn main() {
    let cidr: Cidr = "0.0.0.0/0".parse().unwrap();
    assert_eq!(cidr.to_string(), "0.0.0.0/0".to_owned());
    assert_eq!(cidr.addr(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

    let cidr: Ipv4Cidr = "192.168.0.1/16".parse().unwrap();
    assert_eq!(cidr.to_string(), "192.168.0.0/16".to_owned()); // truncated by default
    assert_eq!(cidr.addr(), Ipv4Addr::new(192, 168, 0, 0));
    assert_eq!(cidr.bits(), 16);

    assert!(cidr.contains(Ipv4Addr::new(192, 168, 0, 1)));
    assert!(!cidr.contains(Ipv4Addr::new(192, 169, 0, 1)));

    assert!(cidr.overlaps(&"192.168.10.0/24".parse().unwrap()));
    assert!(!cidr.overlaps(&"192.167.0.0/16".parse().unwrap()));
}
