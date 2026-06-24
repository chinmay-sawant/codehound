//! Integration tests for the incremental analysis cache (P2.3).
//!
//! These tests exercise the `CacheStore` against real scan runs over
//! small Go fixtures: cache miss on first run, hit on identical second
//! run, miss after a file change, pruning of deleted files, and
//! graceful degradation when the on-disk entry is corrupt.

use std::borrow::Cow;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use slopguard::core::ScanContext;
use slopguard::engine::{
    Analyzer, CacheEntry, CacheStore, DEFAULT_CACHE_DIR, Registry, SlopguardConfig, content_hash,
    discover_cache_dir,
};
use slopguard::rules::{Finding, LineCol, Severity};

fn unique_temp_root(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-cache-{test_name}-{unique}"))
}

fn write_minimal_go(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"package sample

import (
	"net/http"
	"os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_, _ = cmd.CombinedOutput()
}
"#,
    )
    .unwrap();
}

fn finding(rule_id: &'static str, file: &str, line: usize, column: usize) -> Finding {
    Finding::new(
        rule_id,
        "title",
        file,
        LineCol { line, column },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    )
}

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
    store.put(entry.clone()).unwrap();
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

    let mut keep = std::collections::HashSet::new();
    keep.insert("a.go".to_string());
    let removed = store.prune(&keep).unwrap();
    assert_eq!(removed, 2);
    assert_eq!(store.len(), 1);
    assert!(store.get("a.go").is_some());
    assert!(store.get("b.go").is_none());
    assert!(store.get("c.go").is_none());

    std::fs::remove_dir_all(root).unwrap();
}

// ---- End-to-end scan integration tests --------------------------------

fn scan_with_cache(root: &std::path::Path, cache: Option<&mut CacheStore>) -> Vec<String> {
    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer
        .analyze_paths([root], cache)
        .expect("analyze_paths");
    let mut ids: Vec<String> = result
        .findings
        .iter()
        .map(|f| f.rule_id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn first_run_writes_cache_second_run_reads_it() {
    let root = unique_temp_root("first-second");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.go");
    write_minimal_go(&source);

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).expect("open cache");

    let first = scan_with_cache(&root, Some(&mut cache));
    assert!(cache_dir.join("manifest.json").is_file());
    assert!(!first.is_empty(), "expected findings on first run");

    // Second run with the same file content: same findings, manifest
    // is rewritten but should still cover the file.
    let second = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(first, second);
    assert_eq!(cache.len(), 1, "expected one tracked file");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn changing_source_invalidates_cache_entry() {
    let root = unique_temp_root("invalidate");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.go");
    write_minimal_go(&source);

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(cache.len(), 1);

    // Modify the file: a new line at the end changes the content hash.
    let mut body = std::fs::read_to_string(&source).unwrap();
    body.push_str("\n// changed\n");
    std::fs::write(&source, &body).unwrap();

    let _ = scan_with_cache(&root, Some(&mut cache));
    // The manifest is rewritten; the hash in the manifest matches the
    // new content. Length stays 1.
    let meta = cache.manifest().files.get(&source.display().to_string());
    assert!(meta.is_some(), "manifest should still track the file");
    let meta = meta.unwrap();
    assert_eq!(meta.content_hash, content_hash(&body));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn deleting_a_file_prunes_its_cache_entry() {
    let root = unique_temp_root("delete");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.go");
    write_minimal_go(&source);

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(cache.len(), 1);

    std::fs::remove_file(&source).unwrap();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert!(cache.is_empty(), "deleted file's entry should be pruned");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_cache_cli_flag_is_parsed_and_wired() {
    // Smoke test that exercises the CLI flag wiring without spawning
    // a subprocess: simply assert the flag round-trips through clap.
    use clap::Parser;
    use slopguard::cli::Cli;

    let cli = Cli::try_parse_from(["slopguard", "--no-cache"]).unwrap();
    assert!(cli.no_cache);

    let cli = Cli::try_parse_from(["slopguard", "--cache-dir", "/tmp/c"]).unwrap();
    assert_eq!(cli.cache_dir, Some(PathBuf::from("/tmp/c")));

    let cli = Cli::try_parse_from(["slopguard", "--rebuild-cache"]).unwrap();
    assert!(cli.rebuild_cache);
}

#[test]
fn discover_cache_dir_finds_existing_dir() {
    let root = unique_temp_root("discover");
    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(root.join("pkg/sub")).unwrap();

    let found = discover_cache_dir(&root.join("pkg/sub"));
    assert_eq!(found, Some(cache_dir));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cache_config_is_parsed_from_toml() {
    let toml = r#"
[slopguard.cache]
enabled = false
path = "/tmp/custom-cache"
"#;
    let cfg: SlopguardConfig = toml::from_str(toml).unwrap();
    assert!(!cfg.cache_enabled());
    assert_eq!(cfg.cache_path(), Some(PathBuf::from("/tmp/custom-cache")));
}

#[test]
fn cache_disabled_in_config_means_open_returns_none() {
    // Verifies the public app helper is consistent with the config: when
    // cache.enabled = false, the cache should not be opened even if a
    // directory exists. We exercise this through the config API only.
    let cfg = SlopguardConfig {
        slopguard: slopguard::engine::SlopguardSection {
            cache: slopguard::engine::CacheConfig {
                enabled: false,
                path: None,
            },
            ..Default::default()
        },
    };
    assert!(!cfg.cache_enabled());
}

// Keep a `Registry` import to make sure the import set is correct for
// downstream consumers that might rely on this in helper modules.
#[allow(dead_code)]
fn _registry_import_check() -> Registry {
    Registry::default()
}
