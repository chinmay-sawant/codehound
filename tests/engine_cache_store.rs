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
fn entry_metadata_mismatch_is_treated_as_cache_miss() {
    let root = unique_temp_root("entry-metadata-mismatch");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).expect("open");
    let hash = content_hash("body");
    store
        .put("x.go", &hash, &[], vec![], "2026-07-24T00:00:00Z")
        .expect("put");
    store.flush().expect("flush");

    let cache_key = cache_key_for_path("x.go");
    let entry_path = root.join("files").join(format!("{cache_key}.json"));
    let mut entry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&entry_path).expect("read entry")).expect("json");
    entry["content_hash"] = serde_json::Value::String(content_hash("other"));
    std::fs::write(
        &entry_path,
        serde_json::to_vec(&entry).expect("serialize entry"),
    )
    .expect("replace entry");

    assert!(matches!(store.lookup("x.go", &hash), CacheLookup::Stale));
    std::fs::remove_dir_all(root).expect("remove cache");
}

#[test]
fn concurrent_profiles_do_not_merge_each_others_manifest_entries() {
    let root = unique_temp_root("separate-profile-manifests");
    let mut first = CacheStore::open_with_capacity(root.clone(), 500).expect("open first");
    let mut second = CacheStore::open_with_capacity(root.clone(), 500).expect("open second");
    first.ensure_rule_config_hash("profile-a");
    second.ensure_rule_config_hash("profile-b");
    first
        .put(
            "a.go",
            &content_hash("a"),
            &[],
            vec![],
            "2026-07-24T00:00:00Z",
        )
        .expect("put first");
    second
        .put(
            "b.go",
            &content_hash("b"),
            &[],
            vec![],
            "2026-07-24T00:00:00Z",
        )
        .expect("put second");

    second.flush().expect("flush second");
    first.flush().expect("flush first");

    let reopened = CacheStore::open_with_capacity(root.clone(), 500).expect("reopen");
    assert!(reopened.manifest().files.contains_key("a.go"));
    assert!(!reopened.manifest().files.contains_key("b.go"));
    assert!(matches!(
        reopened.lookup("a.go", &content_hash("a")),
        CacheLookup::Hit(_)
    ));
    assert!(matches!(
        reopened.lookup("b.go", &content_hash("b")),
        CacheLookup::Miss
    ));
    std::fs::remove_dir_all(root).expect("remove cache");
}

#[test]
fn flush_reports_manifest_write_failure() {
    let root = unique_temp_root("flush-failure");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).expect("open");
    store
        .put(
            "x.go",
            &content_hash("body"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .expect("put");

    let manifest = root.join("manifest.json");
    std::fs::create_dir(&manifest).expect("replace manifest with directory");
    assert!(
        store.flush().is_err(),
        "manifest write failure must propagate"
    );

    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_manifest_lock_skips_persistence_without_racing_an_older_cache_writer() {
    let root = unique_temp_root("stale-manifest-lock");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).expect("open");
    store
        .put(
            "x.go",
            &content_hash("body"),
            &[],
            vec![],
            "2026-06-10T00:00:00Z",
        )
        .expect("put");
    let lock = root.join(".manifest.lock");
    std::fs::write(&lock, "stale owner").expect("create stale lock");

    store
        .flush()
        .expect("a legacy lock must skip cache persistence, not fail the scan");
    assert!(
        !root.join("manifest.json").exists(),
        "new code must not race a pre-advisory cache writer"
    );

    std::fs::remove_file(lock).expect("remove stale lock");
    store.flush().expect("flush after lock removal");
    assert!(root.join("manifest.json").is_file());

    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn failed_temp_create_preserves_existing_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_root("flush-temp-interrupt");
    let mut store = CacheStore::open_with_capacity(root.clone(), 500).expect("open");
    store
        .put(
            "one.go",
            &content_hash("one"),
            &[],
            vec![],
            "2026-07-23T00:00:00Z",
        )
        .expect("put");
    store.flush().expect("initial flush");
    let manifest = root.join("manifest.json");
    let before = std::fs::read_to_string(&manifest).expect("read prior manifest");

    store
        .put(
            "two.go",
            &content_hash("two"),
            &[],
            vec![],
            "2026-07-23T00:00:01Z",
        )
        .expect("put two");

    let mut perms = std::fs::metadata(&root).expect("meta").permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&root, perms).expect("freeze dir");

    assert!(
        store.flush().is_err(),
        "temp create in a read-only cache dir must fail"
    );

    let mut perms = std::fs::metadata(&root).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&root, perms).expect("thaw dir");

    assert_eq!(
        std::fs::read_to_string(&manifest).expect("reread"),
        before,
        "failed temp write must leave the previous manifest intact"
    );

    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn put_normalizes_dot_slash_manifest_identity() {
    let mut store = CacheStore::in_memory();
    store
        .put(
            "./pkg/x.go",
            &content_hash("body"),
            &["./pkg/y.go".into()],
            vec![],
            "2026-07-23T00:00:00Z",
        )
        .expect("put");
    assert!(store.manifest().files.contains_key("pkg/x.go"));
    assert_eq!(
        store.manifest().files["pkg/x.go"].dependencies,
        vec!["pkg/y.go".to_string()]
    );
    assert_eq!(store.invalidate_dependent("pkg/y.go"), 1);
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
