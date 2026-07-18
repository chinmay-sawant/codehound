//! Verify [`EntrySource`] seam: inject a pre-built entry list via
//! [`ListEntrySource`] and verify the pipeline uses it.

#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{assert_fixture_materializes, unique_temp_root};

use std::sync::Arc;

use codehound::core::LanguageId;
use codehound::engine::{
    Analyzer, CacheSession, CacheStore, EXAMPLE_EXCLUDE_GLOBS, EXAMPLE_FINDING_TAG,
    FilesystemWalker, ListEntrySource, ScanEntry, collect_entries_with,
};
use codehound::engine::{LanguageFilter, PathFilters, Registry};

#[test]
fn list_entry_source_injects_entries_into_analyzer() {
    let root = unique_temp_root("list-entry-source");

    let source_path = assert_fixture_materializes("tests/fixtures/go/perf/PERF-213-vulnerable.txt");
    std::fs::create_dir_all(&root).unwrap();
    let scan_path = root.join("perf_test.go");
    std::fs::copy(&source_path, &scan_path).unwrap();

    let entries = vec![ScanEntry {
        path: Arc::from(scan_path.as_path()),
        language: LanguageId::Go,
    }];

    let source = ListEntrySource::new(entries);
    let analyzer = Analyzer::builder().entry_source(Box::new(source)).build();
    let mut cache = CacheStore::in_memory();
    let result = analyzer
        .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
        .expect("analyze_paths with injected entry source");

    assert!(
        !result.findings.is_empty(),
        "expected findings from injected entry"
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("PERF-")),
        "expected PERF-* findings, got: {:?}",
        result
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn collect_entries_with_list_source_returns_injected_entries() {
    let entries = vec![ScanEntry {
        path: Arc::from(std::path::Path::new("injected.go")),
        language: LanguageId::Go,
    }];
    let source = ListEntrySource::new(entries.clone());
    let registry = Registry::default();
    let (collected, skipped) = collect_entries_with(
        &source,
        &registry,
        &[std::path::Path::new(".")],
        &LanguageFilter::default(),
        &PathFilters::default(),
    )
    .expect("collect via ListEntrySource");

    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].path.as_ref(), entries[0].path.as_ref());
    assert_eq!(skipped, 0);
}

#[test]
fn collect_entries_defaults_to_filesystem_walker() {
    let root = unique_temp_root("filesystem-walker");
    let source_path = assert_fixture_materializes("tests/fixtures/go/perf/PERF-213-vulnerable.txt");
    std::fs::create_dir_all(&root).unwrap();
    let go_path = root.join("sample.go");
    std::fs::copy(&source_path, &go_path).unwrap();

    let registry = Registry::default();
    let (walker_entries, _) = collect_entries_with(
        &FilesystemWalker,
        &registry,
        &[&root],
        &LanguageFilter::default(),
        &PathFilters::default(),
    )
    .expect("filesystem walk");
    assert_eq!(walker_entries.len(), 1);
    assert_eq!(walker_entries[0].path.as_ref(), go_path.as_path());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn findings_under_examples_path_receive_example_tag() {
    let root = unique_temp_root("example-tag");
    let source_path = assert_fixture_materializes("tests/fixtures/go/perf/PERF-213-vulnerable.txt");
    let examples = root.join("examples");
    std::fs::create_dir_all(&examples).unwrap();
    let scan_path = examples.join("demo.go");
    std::fs::copy(&source_path, &scan_path).unwrap();

    let analyzer = Analyzer::builder().build();
    let result = analyzer
        .analyze_paths(&[&root], None)
        .expect("scan examples path");
    assert!(
        !result.findings.is_empty(),
        "expected findings from example demo fixture"
    );
    assert!(
        result.findings.iter().all(|f| {
            f.tags
                .as_ref()
                .is_some_and(|tags| tags.iter().any(|t| t == EXAMPLE_FINDING_TAG))
        }),
        "expected example tag on all findings, got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.file, &f.tags))
            .collect::<Vec<_>>()
    );

    // Optional exclusion is path-based at discovery; default still scans examples.
    let excluded = Analyzer::builder()
        .path_filters(PathFilters {
            exclude: EXAMPLE_EXCLUDE_GLOBS
                .iter()
                .map(|glob| (*glob).to_string())
                .collect(),
            exclude_tests: false,
            ..PathFilters::default()
        })
        .build()
        .analyze_paths(&[&root], None)
        .expect("scan with example excludes");
    assert!(
        excluded.findings.is_empty(),
        "exclude globs should drop example findings: {:?}",
        excluded
            .findings
            .iter()
            .map(|f| &f.file)
            .collect::<Vec<_>>()
    );

    std::fs::remove_dir_all(root).unwrap();
}
