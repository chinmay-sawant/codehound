use std::path::Path;

use codehound::core::ScanContext;
use codehound::engine::{Analyzer, PathFilters};

#[path = "helpers/mod.rs"]
mod helpers;

const FIXTURE_EXT: &str = "txt";

#[test]
fn manifest_entries_exist_and_fire() {
    let manifest = helpers::manifest::load_manifest();

    assert!(
        !manifest.fixture.is_empty(),
        "manifest must list at least one fixture per language"
    );

    for entry in &manifest.fixture {
        assert!(
            entry.path.ends_with(&format!(".{FIXTURE_EXT}")),
            "manifest paths must be .txt text fixtures, not source files: {}",
            entry.path
        );
        assert!(
            Path::new(&entry.path).is_file(),
            "manifest path missing: {} (lang={})",
            entry.path,
            entry.lang
        );
        let rules: Vec<&str> = entry.required_rules.iter().map(String::as_str).collect();
        // Product default is taint off. Core injection/XSS rules are taint-only
        // detectors; enable taint for those fixtures (and explicit `taint = true`).
        const TAINT_CORE: &[&str] = &["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91"];
        let needs_taint = entry.taint
            || entry.path.contains("CWE-")
            || entry.path.contains("/taint/")
            || rules.iter().any(|r| TAINT_CORE.contains(r));
        let ctx = ScanContext {
            taint_enabled: needs_taint,
            ..ScanContext::default()
        };
        let analyzer = Analyzer::builder()
            .scan_context(ctx)
            .path_filters(PathFilters {
                exclude_tests: !fixture_materializes_test_file(&entry.path),
                ..Default::default()
            })
            .build();
        helpers::assert_fixture_rules(&entry.path, &rules, &analyzer);
    }
}

fn fixture_materializes_test_file(txt_path: &str) -> bool {
    std::fs::read_to_string(txt_path)
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("file: ").map(str::trim))
                .map(|file| file.ends_with("_test.go"))
        })
        .unwrap_or(false)
}
