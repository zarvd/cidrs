use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, Criterion};

use cidrs::CidrRoutingTable;

fn match_longest(m: &CidrRoutingTable<String>, addr: IpAddr) -> String {
    m.match_longest(addr).unwrap().1.clone()
}

fn routing_table_match_longest_benchmark(c: &mut Criterion) {
    let table = {
        let mut m = CidrRoutingTable::new();

        let cidr = "0.0.0.0/0".parse().unwrap();
        m.insert(cidr, cidr.to_string());

        for x in 1..255 {
            let cidr = format!("{x}.0.0.0/6").parse().unwrap();
            m.insert(cidr, cidr.to_string());

            let cidr = format!("{x}.0.0.0/7").parse().unwrap();
            m.insert(cidr, cidr.to_string());

            let cidr = format!("{x}.0.0.0/8").parse().unwrap();
            m.insert(cidr, cidr.to_string());

            for y in 0..255 {
                let cidr = format!("{x}.{y}.0.0/9").parse().unwrap();
                m.insert(cidr, cidr.to_string());

                let cidr = format!("{x}.{y}.0.0/11").parse().unwrap();
                m.insert(cidr, cidr.to_string());

                let cidr = format!("{x}.{y}.0.0/13").parse().unwrap();
                m.insert(cidr, cidr.to_string());

                for z in 0..255 {
                    let cidr = format!("{x}.{y}.{z}.0/24").parse().unwrap();
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

criterion_group!(benches, routing_table_match_longest_benchmark,);
criterion_main!(benches);
