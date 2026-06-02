//! Parse + scan throughput on materialized fixtures (local regression signal).

use std::path::Path;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_tree, materialized_root};

fn bench_scan_materialized_fixtures(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    c.bench_function("scan_materialized_fixtures", |b| {
        b.iter(|| {
            analyzer
                .analyze_paths([&root])
                .expect("scan should succeed");
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_scan_materialized_fixtures
}
criterion_main!(benches);
