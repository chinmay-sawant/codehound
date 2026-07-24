#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use helpers::{assert_fixture_materializes, unique_temp_root};

use codehound::core::ScanContext;
use codehound::engine::content_hash;
use codehound::engine::{Analyzer, CacheSession, CacheStore, DEFAULT_CACHE_DIR};

fn copy_fixture_into_root(fixture: &str, root: &Path, output_name: &str) {
    fs::create_dir_all(root).unwrap();
    let source = assert_fixture_materializes(fixture);
    fs::copy(source, root.join(output_name)).unwrap();
}

#[test]
fn concurrent_scans_can_share_a_cache_directory_without_panicking() {
    let root = unique_temp_root("cache-concurrent");
    copy_fixture_into_root(
        "tests/fixtures/go/heuristics/cache/concurrent-command-injection.txt",
        &root,
        "sample.go",
    );

    let cache_dir = Arc::new(root.join(DEFAULT_CACHE_DIR));
    let scan_root = Arc::new(root.clone());
    let mut handles = Vec::new();
    for _ in 0..2 {
        let cache_dir = Arc::clone(&cache_dir);
        let scan_root = Arc::clone(&scan_root);
        handles.push(thread::spawn(move || {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let mut cache = CacheStore::open_with_capacity((*cache_dir).clone(), 500).unwrap();
            let result = analyzer
                .analyze_paths(&[scan_root.as_ref()], Some(CacheSession::open(&mut cache)))
                .unwrap();
            assert!(
                !result.findings.is_empty(),
                "concurrent scan should still produce findings"
            );
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let reopened = CacheStore::open_with_capacity((*cache_dir).clone(), 500).unwrap();
    assert!(reopened.cache_dir().is_dir());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_flushes_preserve_distinct_manifest_entries() {
    let root = unique_temp_root("cache-concurrent-manifest");
    let cache_dir = Arc::new(root.join(DEFAULT_CACHE_DIR));
    let mut handles = Vec::new();
    for file in ["one.go", "two.go"] {
        let cache_dir = Arc::clone(&cache_dir);
        handles.push(thread::spawn(move || {
            let mut cache = CacheStore::open_with_capacity((*cache_dir).clone(), 500).unwrap();
            cache
                .put(
                    file,
                    &content_hash(file),
                    &[],
                    Vec::new(),
                    "2026-07-23T00:00:00Z",
                )
                .unwrap();
            cache.flush().unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let cache = CacheStore::open_with_capacity((*cache_dir).clone(), 500).unwrap();
    assert!(cache.manifest().files.contains_key("one.go"));
    assert!(cache.manifest().files.contains_key("two.go"));
    fs::remove_dir_all(root).unwrap();
}
