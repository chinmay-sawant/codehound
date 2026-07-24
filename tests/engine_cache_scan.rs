#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{assert_fixture_materializes, unique_temp_root, write_go_source};

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use codehound::core::ScanContext;
use codehound::engine::{
    Analyzer, CacheLookup, CacheSession, CacheStore, DEFAULT_CACHE_DIR, content_hash,
    discover_cache_dir,
};

fn copy_fixture_into_root(fixture: &str, root: &Path, output_name: &str) {
    fs::create_dir_all(root).unwrap();
    let source = assert_fixture_materializes(fixture);
    fs::copy(source, root.join(output_name)).unwrap();
}

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
        .analyze_paths(&[root], CacheSession::from_optional(cache))
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
    write_go_source(&source, "");

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 500).expect("open cache");

    let first = scan_with_cache(&root, Some(&mut cache));
    assert!(cache_dir.join("manifest.json").is_file());

    // Second run with the same file content: the same result (including an
    // empty one), and a manifest that still covers the file.
    let second = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(first, second);
    assert_eq!(cache.manifest().files.len(), 1, "expected one tracked file");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn changing_source_invalidates_cache_entry() {
    let root = unique_temp_root("invalidate");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.go");
    write_go_source(&source, "");

    let mut cache = CacheStore::in_memory();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(cache.manifest().files.len(), 1);

    // Modify the file: a new line at the end changes the content hash.
    let mut body = std::fs::read_to_string(&source).unwrap();
    body.push_str("\n// changed\n");
    std::fs::write(&source, &body).unwrap();

    let _ = scan_with_cache(&root, Some(&mut cache));
    // The manifest is rewritten; the hash in the manifest matches the
    // new content. Length stays 1.
    let meta = cache.manifest().files.get("sample.go");
    assert!(meta.is_some(), "manifest should still track the file");
    let meta = meta.unwrap();
    assert_eq!(meta.content_hash, content_hash(&body));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn absolute_scan_path_persists_a_project_relative_cache_identity() {
    let root = unique_temp_root("relative-cache-identity");
    let source = root.join("pkg/sample.go");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    write_go_source(&source, "");

    let mut cache = CacheStore::in_memory();
    let _ = scan_with_cache(&root, Some(&mut cache));

    assert!(cache.manifest().files.contains_key("pkg/sample.go"));
    assert!(
        !cache
            .manifest()
            .files
            .contains_key(&source.display().to_string()),
        "absolute filesystem paths must not become cache identities"
    );
    let hash = cache.manifest().files["pkg/sample.go"].content_hash.clone();
    assert!(matches!(
        cache.lookup("./pkg/sample.go", &hash),
        CacheLookup::Hit(_)
    ));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn narrow_directory_scan_preserves_cache_entries_outside_that_directory() {
    let root = unique_temp_root("narrow-cache-scan");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("go.mod"), "module example.test/cache\n").unwrap();
    fs::create_dir_all(root.join("pkg")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    write_go_source(&root.join("pkg/inside.go"), "");
    write_go_source(&root.join("other/outside.go"), "");

    let mut cache = CacheStore::in_memory();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert!(cache.manifest().files.contains_key("pkg/inside.go"));
    assert!(cache.manifest().files.contains_key("other/outside.go"));

    let _ = scan_with_cache(&root.join("pkg"), Some(&mut cache));

    assert!(cache.manifest().files.contains_key("pkg/inside.go"));
    assert!(
        cache.manifest().files.contains_key("other/outside.go"),
        "a narrow scan must not prune a sibling cache entry"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn absolute_and_relative_roots_invalidate_the_same_project_relative_dependents() {
    let root = unique_temp_root("abs-rel-cascade");
    fs::create_dir_all(root.join("pkg/db")).unwrap();
    fs::write(
        root.join("go.mod"),
        "module example.test/cache\n\ngo 1.22\n",
    )
    .unwrap();
    fs::write(root.join("pkg/db/db.go"), "package db\n\nfunc Open() {}\n").unwrap();
    fs::write(
        root.join("pkg/handler.go"),
        r#"package pkg

import "example.test/cache/pkg/db"

func Handle() { db.Open() }
"#,
    )
    .unwrap();

    let abs_root = root.canonicalize().unwrap();
    let mut cache = CacheStore::in_memory();
    let _ = scan_with_cache(&abs_root, Some(&mut cache));

    let handler = cache
        .manifest()
        .files
        .get("pkg/handler.go")
        .expect("absolute root must persist project-relative handler identity");
    assert!(
        handler
            .dependencies
            .iter()
            .any(|d| d == "pkg/db/db.go" || d.ends_with("pkg/db/db.go")),
        "deps must be project-relative, got {:?}",
        handler.dependencies
    );

    // ./ spelling must hit the same identity and cascade the same edge.
    assert_eq!(cache.invalidate_dependent("./pkg/db/db.go"), 1);
    assert!(
        !cache.manifest().files.contains_key("pkg/handler.go"),
        "relative dependency spelling must invalidate the absolute-root entry"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn deleting_a_file_prunes_its_cache_entry() {
    let root = unique_temp_root("delete");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.go");
    write_go_source(&source, "");

    let mut cache = CacheStore::in_memory();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(cache.manifest().files.len(), 1);

    std::fs::remove_file(&source).unwrap();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert!(
        cache.manifest().files.is_empty(),
        "deleted file's entry should be pruned"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_cache_cli_flag_is_parsed_and_wired() {
    // Smoke test that exercises the CLI flag wiring without spawning
    // a subprocess: simply assert the flag round-trips through clap.
    use clap::Parser;
    use codehound::cli::Cli;

    let cli = Cli::try_parse_from(["codehound", "--no-cache"]).unwrap();
    assert!(cli.no_cache);

    let cli = Cli::try_parse_from(["codehound", "--cache-dir", "/tmp/c"]).unwrap();
    assert_eq!(cli.cache_dir, Some(PathBuf::from("/tmp/c")));

    let cli = Cli::try_parse_from(["codehound", "--rebuild-cache"]).unwrap();
    assert!(cli.rebuild_cache);

    let cli = Cli::try_parse_from(["codehound", "--prune-cache"]).unwrap();
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
fn oversized_files_are_scanned_but_not_cached() {
    let root = unique_temp_root("oversized-skip-cache");
    let source = root.join("sample.go");
    copy_fixture_into_root(
        "tests/fixtures/go/heuristics/cache/oversized-command-injection.txt",
        &root,
        "sample.go",
    );

    let mut body = fs::read_to_string(&source).unwrap();
    body.push_str(&"// pad\n".repeat(220_000));
    fs::write(&source, body).unwrap();

    let mut cache = CacheStore::in_memory_with_limits(500, 0.9, 1);
    let findings = scan_with_cache(&root, Some(&mut cache));

    assert!(
        !findings.is_empty(),
        "oversized file should still be scanned"
    );
    assert!(
        cache.manifest().files.is_empty(),
        "oversized file should not be cached"
    );

    fs::remove_dir_all(root).unwrap();
}
