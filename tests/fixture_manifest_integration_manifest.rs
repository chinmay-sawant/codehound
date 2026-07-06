use std::path::Path;

use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, PathFilters};

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
        let ctx = if entry.taint {
            ScanContext {
                taint_enabled: true,
                ..ScanContext::default()
            }
        } else {
            ScanContext::default()
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
