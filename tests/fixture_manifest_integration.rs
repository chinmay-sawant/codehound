//! Enforces `tests/fixtures/manifest.toml` — every entry must exist and fire rules,
//! and every `.txt` fixture on disk must be listed in the manifest.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use walkdir::WalkDir;

#[path = "helpers/mod.rs"]
mod helpers;

const FIXTURE_EXT: &str = "txt";
const FIXTURES_ROOT: &str = "tests/fixtures";

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

fn load_manifest() -> Manifest {
    let text = std::fs::read_to_string("tests/fixtures/manifest.toml")
        .expect("tests/fixtures/manifest.toml is mandatory");
    toml::from_str(&text).expect("parse manifest.toml")
}

#[test]
fn manifest_entries_exist_and_fire() {
    let manifest = load_manifest();

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
        helpers::assert_fixture_rules(&entry.path, &rules);
    }
}

#[test]
fn manifest_covers_default_languages() {
    let manifest = load_manifest();
    let langs: HashSet<_> = manifest.fixture.iter().map(|e| e.lang.as_str()).collect();

    for lang in ["go", "python"] {
        assert!(
            langs.contains(lang),
            "manifest must include fixture for default language: {lang}"
        );
    }
}

#[test]
fn manifest_includes_every_fixture_on_disk() {
    let manifest = load_manifest();
    let registered: HashSet<&str> = manifest.fixture.iter().map(|e| e.path.as_str()).collect();

    let mut orphans: Vec<String> = Vec::new();
    for entry in WalkDir::new(FIXTURES_ROOT)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let rel = path.to_string_lossy().replace('\\', "/");
        if path.extension().and_then(|s| s.to_str()) == Some(FIXTURE_EXT)
            && !registered.contains(rel.as_str())
        {
            orphans.push(rel.to_string());
        }
    }

    assert!(
        orphans.is_empty(),
        "fixture(s) on disk are not registered in manifest.toml; add them to \
         tests/fixtures/manifest.toml or remove the orphan .txt file: {orphans:#?}"
    );
}
