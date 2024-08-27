use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use cidrs::{Cidr, CidrRoutingTable, Ipv4Cidr};
use criterion::{criterion_group, criterion_main, Criterion};

fn fixture() -> CidrRoutingTable<u64> {
    let mut m = CidrRoutingTable::new();
    let mut v = 0;
    fn next(v: &mut u64) -> u64 {
        *v += 1;
        *v
    }
    m.insert(Ipv4Cidr::new([0, 0, 0, 0], 0).unwrap(), next(&mut v));

    for i1 in 1..128 {
        m.insert(Ipv4Cidr::new([i1, 0, 0, 0], 6).unwrap(), next(&mut v));
        m.insert(Ipv4Cidr::new([i1, 0, 0, 0], 7).unwrap(), next(&mut v));
        m.insert(Ipv4Cidr::new([i1, 0, 0, 0], 8).unwrap(), next(&mut v));

        for i2 in 0..128 {
            m.insert(Ipv4Cidr::new([i1, i2, 0, 0], 9).unwrap(), next(&mut v));
            m.insert(Ipv4Cidr::new([i1, i2, 0, 0], 11).unwrap(), next(&mut v));
            m.insert(Ipv4Cidr::new([i1, i2, 0, 0], 13).unwrap(), next(&mut v));
            for i3 in 0..128 {
                m.insert(Ipv4Cidr::new([i1, i2, i3, 0], 24).unwrap(), next(&mut v));
            }
        }
    }

    m
}

fn match_longest(m: &CidrRoutingTable<u64>, addr: IpAddr) -> u64 {
    *m.match_longest(addr).unwrap().1
}

fn match_longest_benchmark(c: &mut Criterion) {
    let table = fixture();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    c.bench_function("match_longest", |b| {
        b.iter(|| match_longest(&table, black_box(ip)))
    });
}

fn match_exact(m: &CidrRoutingTable<u64>, cidr: Cidr) -> u64 {
    *m.match_exact(cidr).unwrap()
}

fn match_exact_benchmark(c: &mut Criterion) {
    let table = fixture();
    let cidr = Cidr::V4(Ipv4Cidr::new([127, 88, 55, 0], 24).unwrap());
    c.bench_function("match_exact", |b| {
        b.iter(|| match_exact(&table, black_box(cidr)))
    });
}

fn insert(m: &mut CidrRoutingTable<u64>, cidr: Cidr, value: u64) {
    m.insert(cidr, value);
}

fn insert_benchmark(c: &mut Criterion) {
    let cidr = Cidr::V4(Ipv4Cidr::new([127, 88, 55, 240], 32).unwrap());
    c.bench_function("insert", |b| {
        b.iter(|| {
            let mut table = CidrRoutingTable::new();
            insert(&mut table, black_box(cidr), black_box(42));
        })
    });
}

criterion_group!(
    benches,
    match_longest_benchmark,
    match_exact_benchmark,
    insert_benchmark,
);
criterion_main!(benches);
