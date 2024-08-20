mod insert {
    use cidrs::{CidrRoutingTable, Ipv4Cidr, Ipv4CidrRoutingTable, Ipv6Cidr, Ipv6CidrRoutingTable};

    #[test]
    fn ipv4() {
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
    fn ipv6() {
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
    fn simple() {
        let mut table = CidrRoutingTable::new();

        let ipv4_cidr = "192.168.0.0/16".parse::<Ipv4Cidr>().unwrap();
        assert_eq!(table.insert(ipv4_cidr, 1), None);
        assert_eq!(table.insert(ipv4_cidr, 2), Some(1));

        let ipv6_cidr = "2001:db8::/32".parse::<Ipv6Cidr>().unwrap();
        assert_eq!(table.insert(ipv6_cidr, 3), None);
        assert_eq!(table.insert(ipv6_cidr, 4), Some(3));
    }
}

mod match_longest {
    use cidrs::{Ipv4Cidr, Ipv4CidrRoutingTable};

    #[test]
    fn ipv4_simple() {
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
}

mod list_matched {
    use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};

    #[test]
    fn simple() {
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
}

mod len {
    use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};

    #[test]
    fn ipv4_simple_insert() {
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
    fn ipv4_simple_remove() {
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
}
