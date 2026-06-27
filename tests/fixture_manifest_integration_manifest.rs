use std::path::Path;

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;

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
        if entry.taint {
            let ctx = ScanContext {
                taint_enabled: true,
                ..ScanContext::default()
            };
            let analyzer = Analyzer::builder().with_default_filter().scan_context(ctx).build();
            helpers::assert_fixture_rules_with_context(&entry.path, &rules, &analyzer);
        } else {
            helpers::assert_fixture_rules(&entry.path, &rules);
        }
    }
}
