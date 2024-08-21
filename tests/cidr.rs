mod ipv4 {
    mod host_addrs {
        use core::net::Ipv4Addr;

        use cidrs::Ipv4Cidr;

        #[test]
        fn simple() {
            let tests = [
                (([0, 0, 0, 0], 32), vec![[0, 0, 0, 0]]),
                (([1, 0, 2, 0], 32), vec![[1, 0, 2, 0]]),
                (([192, 168, 0, 1], 32), vec![[192, 168, 0, 1]]),
                (([255, 255, 255, 255], 32), vec![[255, 255, 255, 255]]),
                (([0, 0, 0, 0], 31), vec![[0, 0, 0, 0], [0, 0, 0, 1]]),
                (
                    ([1, 1, 1, 0], 30),
                    vec![[1, 1, 1, 0], [1, 1, 1, 1], [1, 1, 1, 2], [1, 1, 1, 3]],
                ),
                (
                    ([255, 255, 255, 254], 31),
                    vec![[255, 255, 255, 254], [255, 255, 255, 255]],
                ),
            ];

            for ((octets, bits), expected) in tests {
                let cidr = Ipv4Cidr::new(octets, bits).unwrap();
                let iter = cidr.hosts();
                assert_eq!(
                    iter.collect::<Vec<_>>(),
                    expected.into_iter().map(Ipv4Addr::from).collect::<Vec<_>>(),
                    "input = {cidr}",
                );
            }
        }
    }
}

mod ipv6 {
    mod host_addrs {
        use core::net::Ipv6Addr;

        use cidrs::Ipv6Cidr;

        #[test]
        fn simple() {
            let tests = [
                (
                    ([0, 0, 0, 0, 0, 0, 0, 0], 128),
                    vec![[0, 0, 0, 0, 0, 0, 0, 0]],
                ),
                (
                    ([0, 0, 0, 0, 0, 0, 0, 0], 127),
                    vec![[0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 1]],
                ),
                (
                    ([0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0], 127),
                    vec![
                        [0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0],
                        [0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 1],
                    ],
                ),
                (
                    ([0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd], 128),
                    vec![[0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd]],
                ),
                (
                    ([0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xff], 128),
                    vec![[0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xff]],
                ),
            ];

            for ((octets, bits), expected) in tests {
                let cidr = Ipv6Cidr::new(octets, bits).unwrap();
                let iter = cidr.hosts();
                assert_eq!(
                    iter.collect::<Vec<_>>(),
                    expected.into_iter().map(Ipv6Addr::from).collect::<Vec<_>>(),
                    "input = {cidr}",
                );
            }
        }
    }
}
