//! Enforces `tests/fixtures/manifest.toml` — every entry must exist and fire rules.

use std::path::Path;

use serde::Deserialize;
use slopguard::engine::Analyzer;

#[path = "helpers/mod.rs"]
mod helpers;

#[derive(Debug, Deserialize)]
struct Manifest {
    fixture: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    lang: String,
    path: String,
    required_rules: Vec<String>,
}

#[test]
fn manifest_entries_exist_and_fire() {
    let text = std::fs::read_to_string("tests/fixtures/manifest.toml")
        .expect("tests/fixtures/manifest.toml is mandatory");
    let manifest: Manifest = toml::from_str(&text).expect("parse manifest.toml");

    assert!(
        !manifest.fixture.is_empty(),
        "manifest must list at least one fixture per language"
    );

    for entry in &manifest.fixture {
        assert!(
            entry.path.ends_with(".txt"),
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
        helpers::assert_fixture_rules(&entry.path, &rules);
    }
}

#[test]
fn manifest_covers_default_languages() {
    let text = std::fs::read_to_string("tests/fixtures/manifest.toml").unwrap();
    let manifest: Manifest = toml::from_str(&text).unwrap();
    let langs: std::collections::HashSet<_> = manifest.fixture.iter().map(|e| e.lang.as_str()).collect();

    for lang in ["go", "python"] {
        assert!(
            langs.contains(lang),
            "manifest must include fixture for default language: {lang}"
        );
    }

    let _ = Analyzer::builder().build();
}
