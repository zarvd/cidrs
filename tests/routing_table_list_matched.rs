use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};

#[test]
fn basic() {
    let mut table = CidrRoutingTable::new();

    let cidr1 = Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap());
    let cidr2 = Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap());
    let cidr3 = Cidr::V4(Ipv4Cidr::new([192, 168, 1, 1], 32).unwrap());

    table.insert(cidr1, 1);
    table.insert(cidr2, 2);
    table.insert(cidr3, 3);

    let matched = table.list_matched([192, 168, 1, 1]);
    assert_eq!(matched, vec![(cidr1, &1), (cidr2, &2), (cidr3, &3)]);

    let matched = table.list_matched([192, 168, 1, 2]);
    assert_eq!(matched, vec![(cidr1, &1), (cidr2, &2)]);

    let matched = table.list_matched([192, 168, 2, 1]);
    assert_eq!(matched, vec![(cidr1, &1)]);

    let matched = table.list_matched([192, 168, 3, 1]);
    assert_eq!(matched, vec![(cidr1, &1)]);

    let matched = table.list_matched([192, 168, 0, 0]);
    assert_eq!(matched, vec![(cidr1, &1)]);

    let matched = table.list_matched([192, 167, 1, 1]);
    assert_eq!(matched, vec![]);
}
