use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};

#[test]
fn ipv4_basic_insert() {
    let mut table = CidrRoutingTable::new();
    let cidr1 = Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap());
    let cidr2 = Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap());

    assert_eq!(table.len(), 0);
    table.insert(cidr1, 1);
    assert_eq!(table.len(), 1);
    table.insert(cidr2, 2);
    assert_eq!(table.len(), 2);
}

#[test]
fn ipv4_insert_existing() {
    let mut table = CidrRoutingTable::new();
    let cidr = Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap());

    assert_eq!(table.len(), 0);
    table.insert(cidr, 1);
    assert_eq!(table.len(), 1);
    table.insert(cidr, 2);
    assert_eq!(table.len(), 1);
}

#[test]
fn ipv4_basic_remove() {
    let mut table = CidrRoutingTable::new();
    let cidr1 = Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap());
    let cidr2 = Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap());

    table.insert(cidr1, 1);
    table.insert(cidr2, 2);
    assert_eq!(table.len(), 2);

    table.remove(cidr1);
    assert_eq!(table.len(), 1);

    table.remove(cidr2);
    assert_eq!(table.len(), 0);
}

#[test]
fn ipv4_remove_non_existing() {
    let mut table = CidrRoutingTable::new();
    let cidr1 = Cidr::V4(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap());
    let cidr2 = Cidr::V4(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap());

    table.insert(cidr1, 1);
    assert_eq!(table.len(), 1);

    table.remove(cidr2);
    assert_eq!(table.len(), 1);

    table.remove(cidr1);
    assert_eq!(table.len(), 0);

    table.remove(cidr1);
    assert_eq!(table.len(), 0);
}
