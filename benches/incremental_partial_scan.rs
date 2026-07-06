use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use slopguard::engine::{CacheStore, collect_entries, content_hash};
use slopguard::fixture::{materialize_tree, materialized_root};

#[path = "common/mod.rs"]
mod common;
use common::{run_scan_with_cache, unique_cache_dir};

fn bench_partial(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize fixtures");
    let root = materialized_root();
    let cache_dir = unique_cache_dir("partial");
    {
        let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 0).unwrap();
        let _ = run_scan_with_cache(root, Some(&mut cache));
    }
    let registry = slopguard::engine::Registry::default();
    let (entries, _skipped) = collect_entries(
        &registry,
        &[&root],
        &slopguard::engine::LanguageFilter::default(),
        &Default::default(),
    )
    .expect("collect");
    let to_change: Vec<std::path::PathBuf> = entries
        .iter()
        .step_by(2)
        .map(|e| e.path.as_ref().to_path_buf())
        .collect();
    let originals: Vec<(std::path::PathBuf, String)> = to_change
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok().map(|s| (p.clone(), s)))
        .collect();
    let changed_paths: HashSet<std::path::PathBuf> = to_change.iter().cloned().collect();
    c.bench_function("incremental_partial_50pct_changed", |b| {
        b.iter(|| {
            for p in &to_change {
                if let Ok(mut body) = std::fs::read_to_string(p) {
                    body.push_str("\n// slopguard-bench-touch\n");
                    std::fs::write(p, &body).unwrap();
                }
            }
            let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 0).unwrap();
            let _ = run_scan_with_cache(root, Some(&mut cache));
            for (p, body) in &originals {
                if changed_paths.contains(p) {
                    std::fs::write(p, body).unwrap();
                }
            }
            let _ = to_change.len();
        });
    });
}

fn bench_cache_hit_in_process(c: &mut Criterion) {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize fixtures");
    let root = materialized_root();
    let mut cache = CacheStore::open_with_capacity(unique_cache_dir("hit-in-mem"), 0).unwrap();
    let _ = run_scan_with_cache(root, Some(&mut cache));
    c.bench_function("incremental_warm_in_memory", |b| {
        b.iter(|| {
            let _ = content_hash("hello");
            let _ = run_scan_with_cache(root, Some(&mut cache));
        });
    });
}

criterion_group! {
    name = incremental_partial;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_partial, bench_cache_hit_in_process
}
criterion_main!(incremental_partial);
