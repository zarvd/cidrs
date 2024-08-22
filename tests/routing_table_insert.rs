use cidrs::{CidrRoutingTable, Ipv4Cidr, Ipv4CidrRoutingTable, Ipv6Cidr, Ipv6CidrRoutingTable};

#[test]
fn ipv4_basic() {
    {
        let mut table = Ipv4CidrRoutingTable::new();
        let cidr = "192.168.0.0/16".parse().unwrap();

        assert_eq!(table.insert(cidr, 1), None);
        assert_eq!(table.insert(cidr, 2), Some(1));
    }

    {
        let mut table = Ipv4CidrRoutingTable::new();
        let cidr1 = "192.168.0.0/16".parse().unwrap();
        let cidr2 = "192.168.1.0/24".parse().unwrap();

        assert_eq!(table.insert(cidr1, 1), None);
        assert_eq!(table.insert(cidr1, 2), Some(1));

        assert_eq!(table.insert(cidr2, 3), None);
        assert_eq!(table.insert(cidr2, 4), Some(3));
    }
}

#[test]
fn ipv6_basic() {
    {
        let mut table = Ipv6CidrRoutingTable::new();
        let cidr = "2001:db8::/32".parse().unwrap();

        assert_eq!(table.insert(cidr, 1), None);
        assert_eq!(table.insert(cidr, 2), Some(1));
    }
    {
        let mut table = Ipv6CidrRoutingTable::new();
        let cidr1 = "2001:db8::/32".parse().unwrap();
        let cidr2 = "2001:db8::1/128".parse().unwrap();

        assert_eq!(table.insert(cidr1, 1), None);
        assert_eq!(table.insert(cidr1, 2), Some(1));

        assert_eq!(table.insert(cidr2, 3), None);
        assert_eq!(table.insert(cidr2, 4), Some(3));
    }
}

#[test]
fn basic() {
    let mut table = CidrRoutingTable::new();

    let ipv4_cidr = "192.168.0.0/16".parse::<Ipv4Cidr>().unwrap();
    assert_eq!(table.insert(ipv4_cidr, 1), None);
    assert_eq!(table.insert(ipv4_cidr, 2), Some(1));

    let ipv6_cidr = "2001:db8::/32".parse::<Ipv6Cidr>().unwrap();
    assert_eq!(table.insert(ipv6_cidr, 3), None);
    assert_eq!(table.insert(ipv6_cidr, 4), Some(3));
}
