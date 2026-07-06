#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{assert_fixture_materializes, unique_temp_root, write_go_source};

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use slopguard::core::ScanContext;
use slopguard::engine::{
    Analyzer, CacheStore, DEFAULT_CACHE_DIR, content_hash, discover_cache_dir,
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
        .analyze_paths(&[root], cache)
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
    assert!(!first.is_empty(), "expected findings on first run");

    // Second run with the same file content: same findings, manifest
    // is rewritten but should still cover the file.
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

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
    let _ = scan_with_cache(&root, Some(&mut cache));
    assert_eq!(cache.manifest().files.len(), 1);

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
    write_go_source(&source, "");

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
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

    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open_with_limits(cache_dir, 500, 0.9, 1).unwrap();
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
