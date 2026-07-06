//! Verify [`EntrySource`] seam: inject a pre-built entry list via
//! [`ListEntrySource`] and verify the pipeline uses it.

#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{assert_fixture_materializes, unique_temp_root};


use std::sync::Arc;

use slopguard::core::LanguageId;
use slopguard::engine::{Analyzer, CacheStore, ListEntrySource, ScanEntry};

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
    let analyzer = Analyzer::builder()
        .entry_source(Box::new(source))
        
        .build();
    let mut cache = CacheStore::in_memory();
    let result = analyzer
        .analyze_paths(&[&root], Some(&mut cache))
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
