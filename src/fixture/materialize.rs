//! Write materialized sources under `target/codehound-fixtures/<pid>-<nanos>/`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use walkdir::WalkDir;

use super::format::{FIXTURE_EXTENSION, TextFixture, parse_fixture};

fn unique_root() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/codehound-fixtures");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    base.join(format!("{pid}-{nanos}"))
}

/// Root directory for generated sources (gitignored).
///
/// Each process gets its own subdirectory, so parallel test binaries cannot
/// race on file writes. The path is stable for the lifetime of the process.
pub fn materialized_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(unique_root)
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
    let root = materialized_root().to_path_buf();
    for entry in WalkDir::new(fixtures_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some(FIXTURE_EXTENSION) {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading fixture {}", path.display()))?;
            let fixture = parse_fixture(&text, path)?;
            write_fixture_at(&root, &fixture)?;
        }
    }
    Ok(root)
}

fn write_fixture(fixture: &TextFixture) -> Result<PathBuf> {
    write_fixture_at(materialized_root(), fixture)
}

fn write_fixture_at(root: &Path, fixture: &TextFixture) -> Result<PathBuf> {
    let out_dir = root.join(fixture.language.as_str());
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(&fixture.filename);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out_path, &fixture.source)
        .with_context(|| format!("writing materialized {}", out_path.display()))?;
    Ok(out_path)
}
