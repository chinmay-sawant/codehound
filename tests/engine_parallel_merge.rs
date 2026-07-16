//! Exercise parallel scan merge through the [`EntrySource`] and
//! [`CacheStore::in_memory`] seams.

#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{assert_fixture_materializes, unique_temp_root};

use std::sync::Arc;

use codehound::core::{LanguageId, ScanContext};
use codehound::engine::{
    Analyzer, CacheSession, CacheStore, ListEntrySource, ScanEntry, content_hash,
};
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

fn perf_fixture_entry(root: &std::path::Path) -> ScanEntry {
    let source_path = assert_fixture_materializes("tests/fixtures/go/perf/PERF-213-vulnerable.txt");
    std::fs::create_dir_all(root).unwrap();
    let scan_path = root.join("perf_test.go");
    std::fs::copy(&source_path, &scan_path).unwrap();
    ScanEntry {
        path: Arc::from(scan_path.as_path()),
        language: LanguageId::Go,
    }
}

#[test]
fn cache_miss_produces_findings_and_tracks_stats() {
    let root = unique_temp_root("parallel-miss");
    let entry = perf_fixture_entry(&root);
    let source = std::fs::read_to_string(entry.path.as_ref()).unwrap();

    let analyzer = Analyzer::builder()
        .entry_source(Box::new(ListEntrySource::new(vec![entry])))
        .collect_stats(true)
        .build();
    let mut cache = CacheStore::in_memory();
    let result = analyzer
        .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
        .expect("cache miss scan");

    assert!(
        !result.findings.is_empty(),
        "expected findings on cache miss"
    );
    let stats = result.stats.expect("stats collected");
    assert_eq!(stats.cache_misses, 1);
    assert_eq!(stats.cache_hits, 0);
    assert_eq!(stats.files_scanned, 1);
    assert!(
        cache
            .manifest()
            .files
            .contains_key(&root.join("perf_test.go").display().to_string())
            || cache.manifest().files.contains_key("perf_test.go"),
        "cache should track scanned file"
    );
    assert_eq!(
        content_hash(&source),
        cache.manifest().files.values().next().unwrap().content_hash
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cache_hit_reuses_stored_findings() {
    let root = unique_temp_root("parallel-hit");
    let entry = perf_fixture_entry(&root);
    let rel = entry.path.display().to_string();
    let source = std::fs::read_to_string(entry.path.as_ref()).unwrap();
    let hash = content_hash(&source);

    let finding = Finding::new(FindingInputs::new(
        "PERF-213",
        "cached",
        &rel,
        LineCol { line: 1, column: 1 },
        "cached finding",
        Severity::Medium,
        std::borrow::Cow::Borrowed(&[]),
    ));

    let mut cache = CacheStore::in_memory();
    cache.ensure_rule_config_hash(&ScanContext::default().rule_config_fingerprint());
    cache
        .put(&rel, &hash, &[], vec![finding], "2020-01-01T00:00:00Z")
        .expect("seed cache");

    let analyzer = Analyzer::builder()
        .entry_source(Box::new(ListEntrySource::new(vec![entry])))
        .collect_stats(true)
        .build();
    let result = analyzer
        .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
        .expect("cache hit scan");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "PERF-213");
    let stats = result.stats.expect("stats collected");
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.cache_misses, 0);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mixed_error_and_ok_entries_merge_errors() {
    let root = unique_temp_root("parallel-errors");
    let good = perf_fixture_entry(&root);
    let bad = ScanEntry {
        path: Arc::from(root.join("missing.go").as_path()),
        language: LanguageId::Go,
    };

    let analyzer = Analyzer::builder()
        .entry_source(Box::new(ListEntrySource::new(vec![good, bad])))
        .build();
    let result = analyzer.analyze_paths(&[&root], None).expect("mixed scan");

    assert!(
        !result.findings.is_empty(),
        "good file should produce findings"
    );
    assert_eq!(result.errors.len(), 1, "missing file should error");

    std::fs::remove_dir_all(root).unwrap();
}
