use std::path::Path;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use codehound::engine::CacheStore;
use codehound::fixture::{materialize_tree, materialized_root};

#[path = "common/mod.rs"]
mod common;
use common::{run_scan_with_cache, unique_cache_dir};

fn bench_cold(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize fixtures");
    let root = materialized_root();
    // Fresh cache directory **per iteration** so cold stays cold
    // (reusing one dir turns later iters into warm hits).
    c.bench_function("incremental_cold", |b| {
        b.iter(|| {
            let cache_dir = unique_cache_dir("cold-iter");
            let mut cache = CacheStore::open_with_capacity(cache_dir, 0).unwrap();
            let _ = run_scan_with_cache(root, Some(&mut cache));
        });
    });
}

fn bench_warm(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize fixtures");
    let root = materialized_root();
    let cache_dir = unique_cache_dir("warm");
    {
        let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 0).unwrap();
        let _ = run_scan_with_cache(root, Some(&mut cache));
    }
    c.bench_function("incremental_warm", |b| {
        b.iter(|| {
            let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 0).unwrap();
            let _ = run_scan_with_cache(root, Some(&mut cache));
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_cold, bench_warm,
}
criterion_main!(benches);
