use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};

#[test]
fn ipv4_basic() {
    let mut table = Ipv4CidrRoutingTable::new();
    table.insert(Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), 1);
    table.insert(Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), 2);
    table.insert(Ipv4Cidr::new([192, 168, 1, 1], 32).unwrap(), 3);

    assert_eq!(
        table.match_longest([192, 168, 1, 1]),
        Some((Ipv4Cidr::new([192, 168, 1, 1], 32).unwrap(), &3))
    );

    assert_eq!(
        table.match_longest([192, 168, 1, 2]),
        Some((Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(), &2))
    );

    assert_eq!(
        table.match_longest([192, 168, 2, 1]),
        Some((Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1))
    );

    assert_eq!(
        table.match_longest([192, 168, 3, 1]),
        Some((Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1))
    );

    assert_eq!(
        table.match_longest([192, 168, 0, 0]),
        Some((Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(), &1))
    );

    assert_eq!(table.match_longest([192, 167, 1, 1]), None);
}

#[test]
fn ipv4_large_data_set() {
    let table = {
        let mut m = Ipv4CidrRoutingTable::new();

        let cidr = Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap();
        m.insert(cidr, cidr.to_string());

        for i1 in 1..128 {
            let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 6).unwrap();
            m.insert(cidr, cidr.to_string());
            let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 7).unwrap();
            m.insert(cidr, cidr.to_string());
            let cidr = Ipv4Cidr::new([i1, 0, 0, 0], 8).unwrap();
            m.insert(cidr, cidr.to_string());

            for i2 in 0..128 {
                let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 9).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 11).unwrap();
                m.insert(cidr, cidr.to_string());
                let cidr = Ipv4Cidr::new([i1, i2, 0, 0], 13).unwrap();
                m.insert(cidr, cidr.to_string());
                for i3 in 0..128 {
                    let cidr = Ipv4Cidr::new([i1, i2, i3, 0], 24).unwrap();
                    m.insert(cidr, cidr.to_string());
                }
            }
        }

        m
    };

    let tests = [
        ([1, 2, 3, 4], Some(([1, 2, 3, 0], 24))),
        ([1, 1, 1, 1], Some(([1, 1, 1, 0], 24))),
        ([1, 0, 129, 1], Some(([1, 0, 0, 0], 13))),
    ];

    for (input, expected) in tests {
        let actual = table.match_longest(input).map(|(k, v)| (k, v.clone()));

        if let Some((octets, bits)) = expected {
            let cidr = Ipv4Cidr::new(octets, bits).unwrap();

            assert_eq!(actual, Some((cidr, cidr.to_string())));
        } else {
            assert_eq!(actual, None);
        }
    }
}
