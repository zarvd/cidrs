use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};

fn main() {
    let mut table = CidrRoutingTable::new();

    table.insert(
        "0.0.0.0/0".parse::<Ipv4Cidr>().unwrap(),
        "route-default".to_owned(),
    );
    table.insert(
        Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(),
        "route-1".to_owned(),
    );
    table.insert(
        Ipv4Cidr::new([10, 0, 0, 1], 32).unwrap(),
        "route-2".to_owned(),
    );
    table.insert(
        Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
        "route-3".to_owned(),
    );

    assert_eq!(
        table.match_longest([192, 168, 0, 1]),
        Some((
            "192.168.0.0/16".parse::<Cidr>().unwrap(),
            &"route-1".to_owned()
        ))
    );

    assert_eq!(
        table.match_longest([192, 168, 1, 1]),
        Some((
            "192.168.1.0/24".parse::<Cidr>().unwrap(),
            &"route-3".to_owned()
        ))
    );

    assert_eq!(
        table.match_longest([1, 1, 1, 1]),
        Some((
            "0.0.0.0/0".parse::<Cidr>().unwrap(),
            &"route-default".to_owned()
        ))
    );
}
