#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::finding;
use helpers::unique_temp_root;

use std::collections::HashSet;

use codehound::engine::{CacheEntry, CacheLookup, CacheStore, cache_key_for_path, content_hash};

fn manifest_len(store: &CacheStore) -> usize {
    store.manifest().files.len()
}

fn cache_get(store: &CacheStore, file: &str) -> Option<CacheEntry> {
    let hash = store.manifest().files.get(file)?.content_hash.clone();
    match store.lookup(file, &hash) {
        CacheLookup::Hit(entry) => Some(entry),
        _ => None,
    }
}

// ── In-memory tests (no filesystem I/O) ──────────────────────────────

#[test]
fn put_then_get_round_trips_findings() {
    let mut store = CacheStore::in_memory();
    let hash = content_hash("hello");
    store
        .put(
            "pkg/a.go",
            &hash,
            &[],
            vec![finding("CWE-78", "pkg/a.go", 10, 5)],
            "2026-06-10T00:00:00Z",
        )
        .unwrap();

    let read = cache_get(&store, "pkg/a.go").expect("entry should be present");
    assert_eq!(read.findings.len(), 1);
    assert_eq!(read.findings[0].rule_id, "CWE-78");
    assert_eq!(read.findings[0].file, "pkg/a.go");
    assert_eq!(read.findings[0].line, 10);
    assert_eq!(read.findings[0].column, 5);
    assert_eq!(read.suppressed_count, 0);
    assert_eq!(
        store.manifest().files["pkg/a.go"].content_hash,
        content_hash("hello")
    );
}

#[test]
fn is_cache_hit_matches_when_hash_matches_and_misses_otherwise() {
    let mut store = CacheStore::in_memory();
    store
        .put(
            "a.go",
            &content_hash("source-v1"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .unwrap();

    assert!(matches!(
        store.lookup("a.go", &content_hash("source-v1")),
        CacheLookup::Hit(_)
    ));
    assert!(!matches!(
        store.lookup("a.go", &content_hash("source-v2")),
        CacheLookup::Hit(_)
    ));
    assert!(!matches!(
        store.lookup("b.go", &content_hash("source-v1")),
        CacheLookup::Hit(_)
    ));
}

#[test]
fn remove_drops_entry_from_manifest() {
    let mut store = CacheStore::in_memory();
    store
        .put("x.go", &content_hash("body"), &[], vec![], "")
        .unwrap();
    assert_eq!(manifest_len(&store), 1);
    store.remove("x.go").unwrap();
    assert!(store.manifest().files.is_empty());
    assert!(cache_get(&store, "x.go").is_none());
}

#[test]
fn flush_is_idempotent_when_not_dirty() {
    let mut store = CacheStore::in_memory();
    store.flush().unwrap();
    store.flush().unwrap();
}

#[test]
fn prune_removes_orphaned_entries() {
    let mut store = CacheStore::in_memory();
    for (name, body) in [("a.go", "alpha"), ("b.go", "beta"), ("c.go", "gamma")] {
        store
            .put(name, &content_hash(body), &[], vec![], "")
            .unwrap();
    }
    assert_eq!(manifest_len(&store), 3);

    let mut keep = HashSet::new();
    keep.insert("a.go".to_string());
    let removed = store.prune(&keep).unwrap();
    assert_eq!(removed, 2);
    assert_eq!(manifest_len(&store), 1);
    assert!(cache_get(&store, "a.go").is_some());
    assert!(cache_get(&store, "b.go").is_none());
    assert!(cache_get(&store, "c.go").is_none());
}

// ── Disk-backed tests (filesystem-specific behaviour) ─────────────────

#[test]
fn open_creates_files_directory_on_empty_path() {
    let root = unique_temp_root("open-empty");
    let store = CacheStore::open_with_capacity(root.clone(), 500).expect("open");

    assert!(root.is_dir(), "cache root was not created");
    assert!(root.join("files").is_dir(), "files/ subdir was not created");
    assert_eq!(manifest_len(&store), 0);
    assert!(store.manifest().files.is_empty());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reopen_loads_existing_manifest() {
    let root = unique_temp_root("reopen");
    let manifest = serde_json::json!({
        "schema_version": 2,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "files": {
            "pkg/handler/user.go": {
                "content_hash": content_hash("body"),
                "dependencies": [],
                "cached_at": "2026-06-10T00:00:00Z"
            }
        }
    });
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let store = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    assert_eq!(manifest_len(&store), 1);
    assert!(store.manifest().files.contains_key("pkg/handler/user.go"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_manifest_falls_back_to_empty() {
    let root = unique_temp_root("corrupt-manifest");
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(root.join("manifest.json"), "{ this is not valid json").unwrap();

    let store = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    assert!(store.manifest().files.is_empty());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_version_mismatch_is_tolerated() {
    let root = unique_temp_root("tool-version-mismatch");
    let manifest = serde_json::json!({
        "schema_version": 2,
        "tool_version": "0.0.0-test",
        "files": {}
    });
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let mut store = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    store
        .put(
            "versioned.go",
            &content_hash("versioned"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .unwrap();
    store.flush().unwrap();

    let reopened = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    assert!(cache_get(&reopened, "versioned.go").is_some());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema_mismatch_returns_error() {
    let root = unique_temp_root("schema-mismatch");
    let manifest = serde_json::json!({
        "schema_version": 999,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "files": {}
    });
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let err = match CacheStore::open_with_capacity(root.clone(), 500) {
        Ok(_) => panic!("expected schema mismatch error"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("unsupported cache schema version"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_entry_file_is_treated_as_cache_miss() {
    let root = unique_temp_root("corrupt-entry");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    store
        .put(
            "x.go",
            &content_hash("body"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .unwrap();
    store.flush().unwrap();

    let cache_key = cache_key_for_path("x.go");
    std::fs::write(
        root.join("files").join(format!("{cache_key}.json")),
        "{not json",
    )
    .unwrap();

    assert!(matches!(
        store.lookup("x.go", &content_hash("body")),
        CacheLookup::Stale
    ));
    assert!(cache_get(&store, "x.go").is_none());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn clean_orphans_removes_untracked_entry_files() {
    let root = unique_temp_root("clean-orphans");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).unwrap();
    store
        .put(
            "tracked.go",
            &content_hash("tracked"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .unwrap();
    store.flush().unwrap();

    std::fs::write(root.join("files").join("orphan.json"), "{}").unwrap();
    let removed = store.clean_orphans().unwrap();
    assert_eq!(removed, 1);
    assert!(!root.join("files").join("orphan.json").exists());
    assert!(cache_get(&store, "tracked.go").is_some());

    std::fs::remove_dir_all(root).unwrap();
}
