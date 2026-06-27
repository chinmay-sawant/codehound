#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::{finding, unique_temp_root};

use std::collections::HashSet;

use slopguard::engine::{CacheEntry, CacheStore, content_hash};

// ---- CacheStore unit-style tests ---------------------------------------

#[test]
fn open_creates_files_directory_on_empty_path() {
    let root = unique_temp_root("open-empty");
    let store = CacheStore::open(root.clone()).expect("open");

    assert!(root.is_dir(), "cache root was not created");
    assert!(root.join("files").is_dir(), "files/ subdir was not created");
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn put_then_get_round_trips_findings() {
    let root = unique_temp_root("round-trip");
    let mut store = CacheStore::open(root.clone()).unwrap();
    let entry = CacheEntry {
        schema_version: slopguard::engine::CACHE_VERSION,
        file: "pkg/a.go".to_string(),
        content_hash: content_hash("hello"),
        mtime_secs: 1,
        mtime_nanos: 0,
        language: "go".to_string(),
        findings: vec![finding("CWE-78", "pkg/a.go", 10, 5)],
        dependencies: Vec::new(),
        cached_at: "2026-06-10T00:00:00Z".to_string(),
    };
    store.put(entry).unwrap();
    store.flush().unwrap();

    let read = store.get("pkg/a.go").expect("entry should be present");
    assert_eq!(read.findings.len(), 1);
    assert_eq!(read.findings[0].rule_id, "CWE-78");
    assert_eq!(read.findings[0].file, "pkg/a.go");
    assert_eq!(read.findings[0].line, 10);
    assert_eq!(read.findings[0].column, 5);
    assert_eq!(read.content_hash, content_hash("hello"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn is_cache_hit_matches_when_hash_matches_and_misses_otherwise() {
    let root = unique_temp_root("hit-miss");
    let mut store = CacheStore::open(root.clone()).unwrap();
    let entry = CacheEntry {
        schema_version: slopguard::engine::CACHE_VERSION,
        file: "a.go".to_string(),
        content_hash: content_hash("source-v1"),
        mtime_secs: 0,
        mtime_nanos: 0,
        language: "go".to_string(),
        findings: vec![],
        dependencies: Vec::new(),
        cached_at: "2026-06-10T00:00:00Z".to_string(),
    };
    store.put(entry).unwrap();

    assert!(store.is_cache_hit("a.go", &content_hash("source-v1")));
    assert!(!store.is_cache_hit("a.go", &content_hash("source-v2")));
    assert!(!store.is_cache_hit("b.go", &content_hash("source-v1")));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn remove_drops_entry_from_manifest_and_disk() {
    let root = unique_temp_root("remove");
    let mut store = CacheStore::open(root.clone()).unwrap();
    let entry = CacheEntry {
        schema_version: slopguard::engine::CACHE_VERSION,
        file: "x.go".to_string(),
        content_hash: content_hash("body"),
        mtime_secs: 0,
        mtime_nanos: 0,
        language: "go".to_string(),
        findings: vec![],
        dependencies: Vec::new(),
        cached_at: "".to_string(),
    };
    store.put(entry).unwrap();
    assert_eq!(store.len(), 1);
    store.remove("x.go").unwrap();
    assert!(store.is_empty());
    assert!(store.get("x.go").is_none());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn flush_is_idempotent_when_not_dirty() {
    let root = unique_temp_root("flush-idempotent");
    let mut store = CacheStore::open(root.clone()).unwrap();
    store.flush().unwrap();
    // No exception: flushing a clean cache is a no-op.
    store.flush().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reopen_loads_existing_manifest() {
    let root = unique_temp_root("reopen");
    let manifest = serde_json::json!({
        "schema_version": 1,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "cache_dir": root.display().to_string(),
        "files": {
            "pkg/handler/user.go": {
                "cache_key": "abc",
                "content_hash": content_hash("body"),
                "mtime_secs": 1234,
                "mtime_nanos": 0,
                "language": "go",
                "dependencies": []
            }
        }
    });
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let store = CacheStore::open(root.clone()).unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.manifest().files.contains_key("pkg/handler/user.go"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_manifest_falls_back_to_empty() {
    let root = unique_temp_root("corrupt-manifest");
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(root.join("manifest.json"), "{ this is not valid json").unwrap();

    let store = CacheStore::open(root.clone()).unwrap();
    assert!(store.is_empty());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema_mismatch_returns_error() {
    let root = unique_temp_root("schema-mismatch");
    let manifest = serde_json::json!({
        "schema_version": 999,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "cache_dir": root.display().to_string(),
        "files": {}
    });
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let err = match CacheStore::open(root.clone()) {
        Ok(_) => panic!("expected schema mismatch error"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("unsupported cache schema version"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn prune_removes_orphaned_entries() {
    let root = unique_temp_root("prune");
    let mut store = CacheStore::open(root.clone()).unwrap();
    for (name, body) in [("a.go", "alpha"), ("b.go", "beta"), ("c.go", "gamma")] {
        let entry = CacheEntry {
            schema_version: slopguard::engine::CACHE_VERSION,
            file: name.to_string(),
            content_hash: content_hash(body),
            mtime_secs: 0,
            mtime_nanos: 0,
            language: "go".to_string(),
            findings: vec![],
            dependencies: Vec::new(),
            cached_at: "".to_string(),
        };
        store.put(entry).unwrap();
    }
    assert_eq!(store.len(), 3);

    let mut keep = HashSet::new();
    keep.insert("a.go".to_string());
    let removed = store.prune(&keep).unwrap();
    assert_eq!(removed, 2);
    assert_eq!(store.len(), 1);
    assert!(store.get("a.go").is_some());
    assert!(store.get("b.go").is_none());
    assert!(store.get("c.go").is_none());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn flush_evicts_oldest_entries_when_over_max_size() {
    let root = unique_temp_root("lru-evict");
    let mut store = CacheStore::open_with_capacity(root.clone(), 1).unwrap();

    // Build enough entries with bulky findings to exceed the 1 MiB limit.
    // Each entry is roughly 12 KiB, so 150 entries ~ 1.8 MiB.
    let bulky_message = "x".repeat(8_000);
    for i in 0..150 {
        let name = format!("file{i:03}.go");
        // Unique minute-stamps so sort order is deterministic and oldest first.
        let stamp = format!("2026-06-10T00:{i:02}:00Z");
        let mut f = finding("CWE-78", &name, 1, 1);
        f.message = bulky_message.clone();
        let entry = CacheEntry {
            schema_version: slopguard::engine::CACHE_VERSION,
            file: name.clone(),
            content_hash: content_hash(&name),
            mtime_secs: 0,
            mtime_nanos: 0,
            language: "go".to_string(),
            findings: vec![f],
            dependencies: Vec::new(),
            cached_at: stamp,
        };
        store.put(entry).unwrap();
    }

    store.flush().unwrap();

    let total = store.total_size();
    assert!(
        total <= 1024 * 1024,
        "cache size {total} should not exceed 1 MiB limit after eviction"
    );

    // The oldest entries should be gone; the newest should survive.
    assert!(
        store.get("file000.go").is_none(),
        "oldest cache entry should be evicted"
    );
    assert!(
        store.get("file001.go").is_none(),
        "second-oldest cache entry should be evicted"
    );
    assert!(
        store.get("file149.go").is_some(),
        "newest cache entry should survive eviction"
    );

    std::fs::remove_dir_all(root).unwrap();
}
