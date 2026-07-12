//! Parse + scan throughput on materialized fixtures (local regression signal).

use std::path::Path;
use std::time::Duration;

use codehound::core::ScanContext;
use codehound::engine::{Analyzer, LanguageFilter, Registry, collect_entries};
use codehound::fixture::{materialize_tree, materialized_root};
use codehound::lang::source_index::SourceIndex;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_scan_materialized_fixtures(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    c.bench_function("scan_materialized_fixtures", |b| {
        b.iter(|| {
            let _ = black_box(
                analyzer
                    .analyze_paths(&[&root], None)
                    .expect("scan should succeed"),
            );
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
            collect_entries(&registry, &[&root], &filter, &Default::default())
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
        // Structural-only: no taint annotations / project accumulate.
        taint_enabled: false,
        ..ScanContext::default()
    };

    let analyzer = Analyzer::builder().scan_context(ctx).build();
    let root = materialized_root();

    c.bench_function("scan_go_only_two_rules", |b| {
        b.iter(|| {
            let _ = black_box(
                analyzer
                    .analyze_paths(&[&root], None)
                    .expect("scan should succeed"),
            );
        });
    });
}

/// Microbench: many `has` lookups against a large needle table (CWE-sized).
fn bench_source_index_has_lookup(c: &mut Criterion) {
    // ~700 synthetic needles (order of CWE table size).
    // Leak once for 'static table (bench-only).
    let needles: &'static [&'static str] = Box::leak(
        (0..700)
            .map(|i| {
                let s = format!("needle_token_{i:04}");
                &*Box::leak(s.into_boxed_str())
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let source = {
        let mut s = String::with_capacity(64 * 1024);
        for i in (0..700).step_by(3) {
            s.push_str(&format!("use needle_token_{i:04};\n"));
        }
        s
    };
    let index = SourceIndex::build(needles, &source);
    // Probe mix of hits and misses.
    let probes: Vec<&str> = (0..700)
        .map(|i| needles[i])
        .chain(std::iter::once("missing_token"))
        .collect();

    c.bench_function("source_index_has_lookup", |b| {
        b.iter(|| {
            let mut hits = 0u32;
            for p in &probes {
                if index.has(black_box(*p)) {
                    hits = hits.wrapping_add(1);
                }
            }
            black_box(hits);
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
        bench_source_index_has_lookup,
}
criterion_main!(benches);
