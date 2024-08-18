use cidrs::CidrRoutingTable;

fn main() {
    let mut table = CidrRoutingTable::new();

    table.insert("0.0.0.0/0".parse().unwrap(), "route-default".to_owned());
    table.insert("192.168.0.0/16".parse().unwrap(), "route-1".to_owned());
    table.insert("10.0.0.1/32".parse().unwrap(), "route-2".to_owned());
    table.insert("192.168.1.0/24".parse().unwrap(), "route-3".to_owned());

    assert_eq!(
        table.match_longest("192.168.0.1".parse().unwrap()),
        Some(("192.168.0.0/16".parse().unwrap(), &"route-1".to_owned()))
    );

    assert_eq!(
        table.match_longest("192.168.1.1".parse().unwrap()),
        Some(("192.168.1.0/24".parse().unwrap(), &"route-3".to_owned()))
    );

    assert_eq!(
        table.match_longest("1.1.1.1".parse().unwrap()),
        Some(("0.0.0.0/0".parse().unwrap(), &"route-default".to_owned()))
    );
}
