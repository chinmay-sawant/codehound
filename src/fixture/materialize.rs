//! Write materialized sources under `target/slopguard-fixtures/`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

use super::format::{parse_fixture, TextFixture, FIXTURE_EXTENSION};

/// Root directory for generated sources (gitignored).
pub fn materialized_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/slopguard-fixtures")
}

/// Read one `.txt` fixture and write `<lang>/<filename>` under the materialized root.
pub fn materialize_fixture(txt_path: &Path) -> Result<PathBuf> {
    let text = fs::read_to_string(txt_path)
        .with_context(|| format!("reading fixture {}", txt_path.display()))?;
    let fixture = parse_fixture(&text, txt_path)?;
    write_fixture(&fixture)
}

/// Materialize every `*.txt` fixture under `fixtures_root`.
pub fn materialize_tree(fixtures_root: &Path) -> Result<PathBuf> {
    for entry in WalkDir::new(fixtures_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some(FIXTURE_EXTENSION) {
            materialize_fixture(path)?;
        }
    }
    Ok(materialized_root())
}

fn write_fixture(fixture: &TextFixture) -> Result<PathBuf> {
    let out_dir = materialized_root().join(fixture.language.as_str());
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(&fixture.filename);
    fs::write(&out_path, &fixture.source)
        .with_context(|| format!("writing materialized {}", out_path.display()))?;
    Ok(out_path)
}
