use cidrs::Ipv4Cidr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn ipv4_fixture() -> Vec<Ipv4Cidr> {
    (0..255)
        .flat_map(|i| {
            (0..=255)
                .map(|j| Ipv4Cidr::new([i, j, 0, 0], 16).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn aggregate_ipv4(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    cidrs::aggregate_ipv4(cidrs)
}

fn aggregate_ipv4_benchmark(c: &mut Criterion) {
    let cidrs: Vec<_> = ipv4_fixture();
    c.bench_function("aggregate_ipv4", |b| {
        b.iter(|| aggregate_ipv4(black_box(&cidrs)))
    });
}

criterion_group!(benches, aggregate_ipv4_benchmark,);
criterion_main!(benches);
