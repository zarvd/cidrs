use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, Criterion};

use cidrs::{CidrRoutingTable, Ipv4Cidr};

fn match_longest(m: &CidrRoutingTable<String>, addr: IpAddr) -> String {
    m.match_longest(addr).unwrap().1.clone()
}

fn routing_table_match_longest_benchmark(c: &mut Criterion) {
    let table = {
        let mut m = CidrRoutingTable::new();

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

    c.bench_function("longest_match", |b| {
        b.iter(|| match_longest(&table, black_box(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))))
    });
}

criterion_group!(benches, routing_table_match_longest_benchmark);
criterion_main!(benches);
