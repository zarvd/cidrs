use core::net::Ipv4Addr;

use cidrs::Ipv4Cidr;

#[test]
fn simple() {
    let tests = [
        (([0, 0, 0, 0], 31), vec![[0, 0, 0, 0], [0, 0, 0, 1]]),
        (([0, 0, 0, 0], 32), vec![[0, 0, 0, 0]]),
        (([1, 0, 2, 0], 32), vec![[1, 0, 2, 0]]),
        (([192, 168, 0, 1], 32), vec![[192, 168, 0, 1]]),
        (([255, 255, 255, 255], 32), vec![[255, 255, 255, 255]]),
        (([1, 1, 1, 0], 30), vec![[1, 1, 1, 1], [1, 1, 1, 2]]),
        (
            ([255, 255, 255, 254], 31),
            vec![[255, 255, 255, 254], [255, 255, 255, 255]],
        ),
        (
            ([0, 0, 0, 0], 24),
            (1..=254).map(|x| [0, 0, 0, x]).collect(),
        ),
        (
            ([255, 255, 255, 0], 24),
            (1..=254).map(|x| [255, 255, 255, x]).collect(),
        ),
        (
            ([10, 0, 0, 0], 24),
            (1..=254).map(|x| [10, 0, 0, x]).collect(),
        ),
    ];

    for ((octets, bits), expected) in tests {
        let cidr = Ipv4Cidr::new(octets, bits).unwrap();
        let actual: Vec<_> = cidr.hosts().collect();
        let expected: Vec<_> = expected.into_iter().map(Ipv4Addr::from).collect();

        assert_eq!(actual, expected, "Mismatch in hosts for CIDR {}", cidr);
        assert_eq!(
            actual.len(),
            cidr.hosts().count(),
            "Mismatch between collected and counted hosts for {}",
            cidr
        );
        assert!(
            actual.first().unwrap() >= &cidr.network_addr(),
            "First host address is before network address for {}",
            cidr
        );
        assert!(
            actual.last().unwrap() <= &cidr.broadcast_addr(),
            "Last host address is after broadcast address for {}",
            cidr
        );
    }
}

mod ipv6 {
    mod hosts {
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
                (
                    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 120),
                    (1..=254)
                        .map(|x| [0x2001, 0xdb8, 0, 0, 0, 0, 0, x])
                        .collect(),
                ),
                (
                    ([0, 0, 0, 0, 0, 0, 0, 0], 120),
                    (1..=254).map(|x| [0, 0, 0, 0, 0, 0, 0, x]).collect(),
                ),
                (
                    ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 120),
                    (1..=254)
                        .map(|x| [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, x])
                        .collect(),
                ),
            ];

            for ((octets, bits), expected) in tests {
                let cidr = Ipv6Cidr::new(octets, bits).unwrap();
                let actual: Vec<_> = cidr.hosts().collect();
                let expected: Vec<_> = expected.into_iter().map(Ipv6Addr::from).collect();

                assert_eq!(actual, expected, "Mismatch in hosts for CIDR {}", cidr);
                assert_eq!(
                    actual.len(),
                    cidr.hosts().count(),
                    "Mismatch between collected and counted hosts for {}",
                    cidr
                );
                assert!(
                    actual.first().unwrap() >= &cidr.network_addr(),
                    "First host address is before network address for {}",
                    cidr
                );
                assert!(
                    actual.last().unwrap() <= &cidr.broadcast_addr(),
                    "Last host address is after broadcast address for {}",
                    cidr
                );
            }
        }
    }
}
