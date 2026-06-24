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
    discover_cache_dir, go_module_prefix,
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
        let mut finding = finding("CWE-78", &name, 1, 1);
        finding.message = bulky_message.clone();
        let entry = CacheEntry {
            schema_version: slopguard::engine::CACHE_VERSION,
            file: name.clone(),
            content_hash: content_hash(&name),
            mtime_secs: 0,
            mtime_nanos: 0,
            language: "go".to_string(),
            findings: vec![finding],
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

// ---- End-to-end scan integration tests --------------------------------

fn scan_with_cache(root: &std::path::Path, cache: Option<&mut CacheStore>) -> Vec<String> {
    scan_with_context(root, cache, ScanContext::default())
}

fn scan_with_context(
    root: &std::path::Path,
    cache: Option<&mut CacheStore>,
    ctx: ScanContext,
) -> Vec<String> {
    let analyzer = Analyzer::builder().scan_context(ctx).build();
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

    let cli = Cli::try_parse_from(["slopguard", "--prune-cache"]).unwrap();
    assert!(cli.prune_cache);
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
                ..Default::default()
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

// ---- Dependency extraction + transitive invalidation -------------------

mod dep_helpers {
    use slopguard::core::LanguagePlugin;
    use slopguard::engine::{extract_dependencies, go_module_prefix};
    use slopguard::lang::go::GoPlugin;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn unique_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("slopguard-dep-{label}-{unique}"))
    }

    pub fn write_file(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    pub fn parse_go(project: &Path, rel: &str) -> (slopguard::core::ParsedUnit, Option<String>) {
        let path = project.join(rel);
        let source = std::fs::read_to_string(&path).unwrap();
        let plugin = GoPlugin;
        let mut parser = tree_sitter::Parser::new();
        plugin.configure_parser(&mut parser);
        let unit = plugin
            .parse_with(&mut parser, &path, Arc::from(source.as_str()))
            .unwrap();
        let module = go_module_prefix(project);
        (unit, module)
    }

    pub fn deps_for(project: &Path, rel: &str) -> Vec<String> {
        let (unit, module) = parse_go(project, rel);
        extract_dependencies(&unit, project, module.as_deref())
    }
}

#[test]
fn go_dependency_extraction_finds_local_package() {
    use dep_helpers::*;
    let root = unique_root("local-pkg");
    std::fs::create_dir_all(root.join("pkg/db")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(&root.join("pkg/db/db.go"), "package db\n\nfunc Open() {}\n");
    write_file(
        &root.join("pkg/handler/handler.go"),
        r#"package handler

import "example.com/proj/pkg/db"

func Run() { db.Open() }
"#,
    );
    let deps = deps_for(&root, "pkg/handler/handler.go");
    assert!(
        deps.iter().any(|d| d.ends_with("pkg/db/db.go")),
        "expected handler to depend on db.go, got {deps:?}"
    );
}

#[test]
fn go_dependency_extraction_skips_stdlib_and_third_party() {
    use dep_helpers::*;
    let root = unique_root("skip-stdlib");
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(
        &root.join("pkg/x.go"),
        r#"package x

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)
"#,
    );
    let deps = deps_for(&root, "pkg/x.go");
    assert!(deps.is_empty(), "expected no local deps, got {deps:?}");
}

#[test]
fn go_dependency_extraction_handles_directory_import() {
    use dep_helpers::*;
    let root = unique_root("dir-import");
    std::fs::create_dir_all(root.join("pkg/handlers")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(&root.join("pkg/handlers/a.go"), "package handlers\n");
    write_file(&root.join("pkg/handlers/b.go"), "package handlers\n");
    write_file(
        &root.join("main.go"),
        r#"package main

import "example.com/proj/pkg/handlers"
"#,
    );
    let deps = deps_for(&root, "main.go");
    assert_eq!(
        deps.len(),
        2,
        "expected 2 files in pkg/handlers, got {deps:?}"
    );
    assert!(deps.iter().any(|d| d.ends_with("pkg/handlers/a.go")));
    assert!(deps.iter().any(|d| d.ends_with("pkg/handlers/b.go")));
}

#[test]
fn go_module_prefix_returns_none_for_missing_go_mod() {
    use dep_helpers::*;
    let root = unique_root("no-go-mod");
    std::fs::create_dir_all(&root).unwrap();
    assert!(go_module_prefix(&root).is_none());
}

#[test]
fn transitive_invalidation_clears_dependents() {
    use dep_helpers::*;
    use slopguard::core::ScanContext;
    use slopguard::engine::discover_cache_dir;
    use slopguard::engine::{Analyzer, CacheStore, DEFAULT_CACHE_DIR};

    let root = unique_root("transitive");
    std::fs::create_dir_all(root.join("pkg/db")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(
        &root.join("pkg/db/db.go"),
        r#"package db

import "os/exec"

func Run() { exec.Command("sh", "-c", "ls").Run() }
"#,
    );
    write_file(
        &root.join("pkg/handler.go"),
        r#"package handler

import "example.com/proj/pkg/db"

func Handle() { db.Run() }
"#,
    );

    // First scan: both files end up in the manifest, and handler.go
    // declares db.go as a dependency.
    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();
    {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let _ = analyzer.analyze_paths([&root], Some(&mut cache)).unwrap();
    }
    cache.flush().unwrap();

    let manifest = cache.manifest();
    let handler_entry = manifest
        .files
        .iter()
        .find(|(k, _)| k.ends_with("pkg/handler.go"))
        .map(|(_, v)| v.clone())
        .expect("handler.go in manifest after first scan");
    assert!(
        handler_entry
            .dependencies
            .iter()
            .any(|d| d.ends_with("db.go")),
        "handler.go should depend on db.go, deps were {:?}",
        handler_entry.dependencies
    );

    // Edit db.go: its content hash will change on the next scan,
    // which means handler.go's cache entry must be invalidated via
    // the transitive invalidation hook.
    let mut db_src = std::fs::read_to_string(root.join("pkg/db/db.go")).unwrap();
    db_src.push_str("\n// touch\n");
    std::fs::write(root.join("pkg/db/db.go"), &db_src).unwrap();

    let mut cache2 = CacheStore::open(cache_dir).unwrap();
    {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let _ = analyzer.analyze_paths([&root], Some(&mut cache2)).unwrap();
    }
    let m2 = cache2.manifest();
    // After invalidation, handler.go's manifest entry is dropped,
    // so the next read will re-parse it from scratch.
    let handler_key = m2
        .files
        .keys()
        .find(|k| k.ends_with("pkg/handler.go"))
        .cloned();
    assert!(
        handler_key.is_none(),
        "handler.go should have been cascade-invalidated; still in manifest: {handler_key:?}"
    );
    // db.go was rescanned and is back in the manifest.
    assert!(
        m2.files.keys().any(|k| k.ends_with("pkg/db/db.go")),
        "db.go should be re-tracked after re-scan"
    );

    // discover_cache_dir should locate the existing cache root.
    let found = discover_cache_dir(&root.join("pkg"));
    assert_eq!(found, Some(root.join(DEFAULT_CACHE_DIR)));
}

#[test]
fn inline_ignore_re_applied_on_cache_hit() {
    use dep_helpers::*;
    use slopguard::core::ScanContext;
    use slopguard::engine::Analyzer;

    let root = unique_root("inline-ignore-cache");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    // Vulnerable Go code: command injection via exec.Command.
    // First run: no inline-ignore -> finding is emitted and cached.
    write_file(
        &root.join("cmd.go"),
        r#"package cmd

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
    );

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();
    let first_count = {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let r = analyzer.analyze_paths([&root], Some(&mut cache)).unwrap();
        r.findings.len()
    };
    cache.flush().unwrap();
    assert!(
        first_count > 0,
        "expected findings on first scan; cache should record the result"
    );

    // Second run with a file-level slopguard-ignore-file
    // directive added. The cache hit (or, more likely, the cache
    // miss that re-parses the file because the hash changed)
    // must drop every CWE-78 finding even though the cache entry
    // was written with the old code.
    let mut src = std::fs::read_to_string(root.join("cmd.go")).unwrap();
    src.insert_str(0, "// slopguard-ignore-file: CWE-78\n");
    std::fs::write(root.join("cmd.go"), &src).unwrap();

    let mut cache2 = CacheStore::open(cache_dir).unwrap();
    let (second_count, cwe78_in_second) = {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let r = analyzer.analyze_paths([&root], Some(&mut cache2)).unwrap();
        let cwes: Vec<&str> = r
            .findings
            .iter()
            .map(|f| f.rule_id)
            .filter(|id| *id == "CWE-78")
            .collect();
        (r.findings.len(), cwes.len())
    };
    assert!(
        cwe78_in_second == 0,
        "inline-ignore on CWE-78 should drop the CWE-78 finding on cache hit, \
         but {cwe78_in_second} remained (total findings: {second_count})"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inline_ignore_applied_on_cache_hit_when_source_unchanged() {
    use dep_helpers::*;
    use slopguard::core::ScanContext;
    use slopguard::engine::Analyzer;

    let root = unique_root("inline-cache-hit");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    // The file starts with a file-level ignore. Both runs scan
    // identical source, so the second run is a true cache hit.
    write_file(
        &root.join("cmd.go"),
        "// slopguard-ignore-file: CWE-78\npackage cmd\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc Run(w http.ResponseWriter, r *http.Request) {\n\thost := r.URL.Query().Get(\"host\")\n\tcmd := exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host)\n\t_, _ = cmd.CombinedOutput()\n}\n",
    );

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();
    {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let _ = analyzer.analyze_paths([&root], Some(&mut cache)).unwrap();
    }
    cache.flush().unwrap();

    // Re-open the cache, re-run with the same source. The hash
    // matches so the cache hit path is taken.
    let mut cache2 = CacheStore::open(cache_dir).unwrap();
    let cwe78 = {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let r = analyzer.analyze_paths([&root], Some(&mut cache2)).unwrap();
        r.findings.iter().filter(|f| f.rule_id == "CWE-78").count()
    };
    assert_eq!(
        cwe78, 0,
        "CWE-78 must be filtered by slopguard-ignore-file on cache hit"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn skip_flag_filters_cached_findings() {
    use dep_helpers::*;
    use slopguard::core::ScanContext;
    use slopguard::engine::Analyzer;

    let root = unique_root("skip-cache-hit");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(
        &root.join("cmd.go"),
        r#"package cmd

import (
	"net/http"
	"os"
	"os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_, _ = cmd.CombinedOutput()
}

func ReadFile(r *http.Request) {
	name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(name)
	_ = data
}
"#,
    );

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open(cache_dir.clone()).unwrap();

    let first_ids = {
        let analyzer = Analyzer::builder()
            .scan_context(ScanContext::default())
            .build();
        let r = analyzer.analyze_paths([&root], Some(&mut cache)).unwrap();
        let mut ids: Vec<String> = r.findings.iter().map(|f| f.rule_id.to_string()).collect();
        ids.sort();
        ids.dedup();
        ids
    };
    cache.flush().unwrap();
    assert!(
        first_ids.len() > 1,
        "expected at least 2 distinct rule IDs, got {first_ids:?}"
    );

    let skipped_rule = first_ids[0].clone();
    let mut skip_set = std::collections::HashSet::new();
    skip_set.insert(skipped_rule.clone());

    let mut cache2 = CacheStore::open(cache_dir).unwrap();
    let second_ids = {
        let ctx = ScanContext {
            skip: skip_set,
            ..Default::default()
        };
        let analyzer = Analyzer::builder().scan_context(ctx).build();
        let r = analyzer.analyze_paths([&root], Some(&mut cache2)).unwrap();
        let mut ids: Vec<String> = r.findings.iter().map(|f| f.rule_id.to_string()).collect();
        ids.sort();
        ids.dedup();
        ids
    };

    assert!(
        !second_ids.contains(&skipped_rule),
        "skipped rule {skipped_rule} should not appear on cache hit; got {second_ids:?}"
    );
    assert!(
        second_ids.len() < first_ids.len(),
        "second run (with --skip) should have fewer distinct rule IDs than first run"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn debug_dependency_extraction() {
    // Sanity test against a real on-disk project. Useful as a
    // manual smoke check; not part of the standard suite because
    // it depends on the gopdfsuit checkout existing at a fixed path.
    use slopguard::core::LanguagePlugin;
    use slopguard::engine::{discover_project_root, extract_dependencies, go_module_prefix};
    use slopguard::lang::go::GoPlugin;
    use std::sync::Arc;

    let project = discover_project_root(std::path::Path::new(
        "/home/chinmay/ChinmayPersonalProjects/gopdfsuit",
    ));
    let module = go_module_prefix(&project);
    eprintln!("project_root: {project:?}");
    eprintln!("module_prefix: {module:?}");

    let path = project.join("pkg/gopdflib/redact.go");
    let source = std::fs::read_to_string(&path).expect("read source");
    let plugin = GoPlugin;
    let mut parser = tree_sitter::Parser::new();
    plugin.configure_parser(&mut parser);
    let unit = plugin
        .parse_with(&mut parser, &path, Arc::from(source.as_str()))
        .expect("parse");
    let deps = extract_dependencies(&unit, &project, module.as_deref());
    eprintln!("deps for redact.go: {deps:#?}");
    // This file imports two local packages, so it should have deps.
    assert!(!deps.is_empty(), "expected deps for redact.go");
}
#[test]
fn debug_discover_project_root() {
    use slopguard::engine::discover_project_root;
    let tmp = std::env::temp_dir().join("slopguard-test-no-git-here");
    std::fs::create_dir_all(&tmp).unwrap();
    let discovered = discover_project_root(&tmp);
    eprintln!("discovered for {tmp:?}: {discovered:?}");
    let with_git = std::env::temp_dir().join("slopguard-test-with-git");
    std::fs::create_dir_all(with_git.join(".git")).unwrap();
    let discovered2 = discover_project_root(&with_git);
    eprintln!("discovered for {with_git:?}: {discovered2:?}");
    std::fs::remove_dir_all(&tmp).unwrap();
    std::fs::remove_dir_all(&with_git).unwrap();
}
