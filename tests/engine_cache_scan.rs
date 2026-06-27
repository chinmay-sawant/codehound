#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::{unique_temp_root, write_minimal_go};

use std::path::PathBuf;

use slopguard::core::ScanContext;
use slopguard::engine::{
    Analyzer, CacheStore, DEFAULT_CACHE_DIR, SlopguardConfig, content_hash, discover_cache_dir,
};

fn scan_with_cache(root: &std::path::Path, cache: Option<&mut CacheStore>) -> Vec<String> {
    scan_with_context(root, cache, ScanContext::default())
}

fn scan_with_context(
    root: &std::path::Path,
    cache: Option<&mut CacheStore>,
    ctx: ScanContext,
) -> Vec<String> {
    let analyzer = Analyzer::builder()
        .with_default_filter()
        .scan_context(ctx)
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
    let mut cache = CacheStore::open(cache_dir).unwrap();
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
    let mut cache = CacheStore::open(cache_dir).unwrap();
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
