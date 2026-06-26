use std::collections::HashSet;

use walkdir::WalkDir;

#[path = "helpers/mod.rs"]
mod helpers;

const FIXTURE_EXT: &str = "txt";
const FIXTURES_ROOT: &str = "tests/fixtures";

#[test]
fn manifest_covers_default_languages() {
    let manifest = helpers::manifest::load_manifest();
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
    let manifest = helpers::manifest::load_manifest();
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
