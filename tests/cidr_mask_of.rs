use cidrs::{Ipv4Cidr, Ipv6Cidr};

#[test]
fn ipv4_basic() {
    let tests = [
        (0, [0, 0, 0, 0]),
        (1, [0x80, 0, 0, 0]),
        (2, [0xc0, 0, 0, 0]),
        (3, [0xe0, 0, 0, 0]),
        (4, [0xf0, 0, 0, 0]),
        (5, [0xf8, 0, 0, 0]),
        (6, [0xfc, 0, 0, 0]),
        (7, [0xfe, 0, 0, 0]),
        (8, [0xff, 0, 0, 0]),
        (9, [0xff, 0x80, 0, 0]),
        (10, [0xff, 0xc0, 0, 0]),
        (11, [0xff, 0xe0, 0, 0]),
        (12, [0xff, 0xf0, 0, 0]),
        (13, [0xff, 0xf8, 0, 0]),
        (14, [0xff, 0xfc, 0, 0]),
        (15, [0xff, 0xfe, 0, 0]),
        (16, [0xff, 0xff, 0, 0]),
        (17, [0xff, 0xff, 0x80, 0]),
        (18, [0xff, 0xff, 0xc0, 0]),
        (19, [0xff, 0xff, 0xe0, 0]),
        (20, [0xff, 0xff, 0xf0, 0]),
        (21, [0xff, 0xff, 0xf8, 0]),
        (22, [0xff, 0xff, 0xfc, 0]),
        (23, [0xff, 0xff, 0xfe, 0]),
        (24, [0xff, 0xff, 0xff, 0]),
        (25, [0xff, 0xff, 0xff, 0x80]),
        (26, [0xff, 0xff, 0xff, 0xc0]),
        (27, [0xff, 0xff, 0xff, 0xe0]),
        (28, [0xff, 0xff, 0xff, 0xf0]),
        (29, [0xff, 0xff, 0xff, 0xf8]),
        (30, [0xff, 0xff, 0xff, 0xfc]),
        (31, [0xff, 0xff, 0xff, 0xfe]),
        (32, [0xff, 0xff, 0xff, 0xff]),
    ];

    for (bits, expected) in tests {
        let actual = Ipv4Cidr::mask_of(bits);
        let expected = u32::from_be_bytes(expected);
        assert_eq!(actual, expected, "bit: {bits}");
    }
}

#[test]
#[should_panic(expected = "bits must be <= 32")]
fn ipv4_panic_33() {
    Ipv4Cidr::mask_of(33);
}

#[test]
#[should_panic(expected = "bits must be <= 32")]
fn ipv4_panic_255() {
    Ipv4Cidr::mask_of(255);
}

#[test]
fn ipv6_basic() {
    let tests = [
        (0, [0; 16]),
        (1, [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        (8, [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        (16, [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        (
            23,
            [0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            32,
            [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            47,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (
            64,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (
            79,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (
            96,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
            ],
        ),
        (
            113,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x80, 0,
            ],
        ),
        (128, [0xff; 16]),
    ];

    for (bits, expected) in tests {
        let actual = Ipv6Cidr::mask_of(bits);
        let expected = u128::from_be_bytes(expected);
        assert_eq!(actual, expected, "bit: {bits}");
    }
}

#[test]
#[should_panic(expected = "bits must be <= 128")]
fn ipv6_panic_129() {
    Ipv6Cidr::mask_of(129);
}

#[test]
#[should_panic(expected = "bits must be <= 128")]
fn ipv6_panic_255() {
    Ipv6Cidr::mask_of(255);
}
