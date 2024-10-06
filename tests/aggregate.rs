use cidrs::{aggregate_ipv4, Ipv4Cidr};

#[test]
fn ipv4_basic() {
    let tests = [
        (
            vec![Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()],
            vec![Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()],
        ),
        (
            vec![
                Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
            ],
            vec![Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()],
        ),
        (
            vec![
                Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
            ],
            vec![Ipv4Cidr::new([192, 168, 0, 0], 23).unwrap()],
        ),
        (
            vec![
                Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 1, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 2, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 3, 0], 24).unwrap(),
            ],
            vec![Ipv4Cidr::new([192, 168, 0, 0], 22).unwrap()],
        ),
        (
            vec![
                Ipv4Cidr::new([10, 0, 0, 0], 8).unwrap(),
                Ipv4Cidr::new([172, 16, 0, 0], 12).unwrap(),
                Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(),
            ],
            vec![
                Ipv4Cidr::new([10, 0, 0, 0], 8).unwrap(),
                Ipv4Cidr::new([172, 16, 0, 0], 12).unwrap(),
                Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap(),
            ],
        ),
        (
            vec![
                Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap(),
                Ipv4Cidr::new([192, 168, 0, 128], 25).unwrap(),
            ],
            vec![Ipv4Cidr::new([192, 168, 0, 0], 24).unwrap()],
        ),
    ];

    for (input, expected) in tests {
        let actual = aggregate_ipv4(&input);
        assert_eq!(actual, expected, "input: {input:?}");
    }
}

#[test]
fn ipv4_full() {
    {
        let cidrs: Vec<Ipv4Cidr> = (0..=255)
            .flat_map(|i| {
                (0..=255)
                    .map(|j| Ipv4Cidr::new([i, j, 0, 0], 16).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();

        let expected = vec![Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap()];
        let actual = aggregate_ipv4(&cidrs);
        assert_eq!(actual, expected);
    }

    {
        let cidrs: Vec<Ipv4Cidr> = (0..=255)
            .flat_map(|i| {
                (0..=255)
                    .map(|j| Ipv4Cidr::new([192, 168, i, j], 32).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();

        let expected = vec![Ipv4Cidr::new([192, 168, 0, 0], 16).unwrap()];
        let actual = aggregate_ipv4(&cidrs);
        assert_eq!(actual, expected);
    }
}
