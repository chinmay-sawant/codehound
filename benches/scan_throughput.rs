//! Parse + scan throughput on materialized fixtures (local regression signal).

use std::path::Path;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, LanguageFilter, Registry, collect_entries};
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
                .analyze_paths([&root], None)
                .expect("scan should succeed");
        });
    });
}

fn bench_collect_entries_only(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let registry = Registry::default();
    let filter = LanguageFilter::default();
    let root = materialized_root();

    c.bench_function("collect_entries_materialized", |b| {
        b.iter(|| {
            collect_entries(&registry, [&root], &filter, &Default::default())
                .expect("collect entries");
        });
    });
}

fn bench_scan_go_only_subset(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let ctx = ScanContext {
        only: Some(
            ["CWE-22", "CWE-89"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        ),
        ..ScanContext::default()
    };

    let analyzer = Analyzer::builder().scan_context(ctx).build();
    let root = materialized_root();

    c.bench_function("scan_go_only_two_rules", |b| {
        b.iter(|| {
            analyzer
                .analyze_paths([&root], None)
                .expect("scan should succeed");
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets =
        bench_scan_materialized_fixtures,
        bench_collect_entries_only,
        bench_scan_go_only_subset,
}
criterion_main!(benches);
