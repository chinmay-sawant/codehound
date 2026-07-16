//! Write materialized sources under `target/codehound-fixtures/<pid>-<nanos>/`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use super::format::{FIXTURE_EXTENSION, FixtureError, TextFixture, parse_fixture};

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
///
/// # Errors
///
/// Returns [`FixtureError`] when the fixture cannot be read, parsed, or safely
/// materialized.
pub fn materialize_fixture(txt_path: &Path) -> Result<PathBuf, FixtureError> {
    let text = fs::read_to_string(txt_path).map_err(|source| FixtureError::Io {
        operation: "reading fixture",
        path: txt_path.display().to_string(),
        source,
    })?;
    let fixture = parse_fixture(&text, txt_path)?;
    write_fixture(&fixture)
}

/// Materialize every `*.txt` fixture under `fixtures_root`.
///
/// # Errors
///
/// Returns [`FixtureError`] when traversal, reading, parsing, or writing fails.
pub fn materialize_tree(fixtures_root: &Path) -> Result<PathBuf, FixtureError> {
    let root = materialized_root().to_path_buf();
    for entry in WalkDir::new(fixtures_root) {
        let entry = entry.map_err(|error| FixtureError::Walk(error.to_string()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some(FIXTURE_EXTENSION) {
            let text = fs::read_to_string(path).map_err(|source| FixtureError::Io {
                operation: "reading fixture",
                path: path.display().to_string(),
                source,
            })?;
            let fixture = parse_fixture(&text, path)?;
            write_fixture_at(&root, &fixture)?;
        }
    }
    Ok(root)
}

fn write_fixture(fixture: &TextFixture) -> Result<PathBuf, FixtureError> {
    write_fixture_at(materialized_root(), fixture)
}

/// Reject fixture filenames that escape the materialize root (`..` or absolute).
fn sanitize_fixture_filename(filename: &str) -> Result<&Path, FixtureError> {
    let path = Path::new(filename);
    if path.is_absolute() {
        return Err(FixtureError::AbsoluteFilename(filename.to_string()));
    }
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(FixtureError::ParentFilename(filename.to_string()));
        }
    }
    Ok(path)
}

fn write_fixture_at(root: &Path, fixture: &TextFixture) -> Result<PathBuf, FixtureError> {
    let filename = sanitize_fixture_filename(&fixture.filename)?;
    let out_dir = root.join(fixture.language.as_str());
    fs::create_dir_all(&out_dir).map_err(|source| FixtureError::Io {
        operation: "creating fixture directory",
        path: out_dir.display().to_string(),
        source,
    })?;
    let out_path = out_dir.join(filename);
    // Ensure the resolved path still lives under out_dir (defense in depth).
    let out_canon_parent = out_dir.canonicalize().map_err(|source| FixtureError::Io {
        operation: "resolving fixture directory",
        path: out_dir.display().to_string(),
        source,
    })?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|source| FixtureError::Io {
            operation: "creating fixture directory",
            path: parent.display().to_string(),
            source,
        })?;
        let parent_check = parent.canonicalize().map_err(|source| FixtureError::Io {
            operation: "resolving fixture directory",
            path: parent.display().to_string(),
            source,
        })?;
        if !parent_check.starts_with(&out_canon_parent) {
            return Err(FixtureError::EscapedPath(out_path.display().to_string()));
        }
    }
    fs::write(&out_path, &fixture.source).map_err(|source| FixtureError::Io {
        operation: "writing materialized fixture",
        path: out_path.display().to_string(),
        source,
    })?;
    Ok(out_path)
}
