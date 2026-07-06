//! Shared path/fixture helpers for Go bad-practice detectors.

use std::path::PathBuf;

use walkdir::WalkDir;

use crate::core::ParsedUnit;
use crate::engine::discover_project_root;

pub(crate) fn is_test_file(unit: &ParsedUnit) -> bool {
    unit.display_path.ends_with("_test.go")
}

pub(crate) fn is_materialized_fixture(unit: &ParsedUnit) -> bool {
    let display = unit.display_path.as_str();
    display.contains("target/slopguard-fixtures/")
        || display.contains("target\\slopguard-fixtures\\")
}

pub(crate) fn is_flat_materialized_fixture(unit: &ParsedUnit) -> bool {
    let display = unit.display_path.as_str();
    let materialized = display.contains("target/slopguard-fixtures/")
        || display.contains("target\\slopguard-fixtures\\");
    let parent_is_language_root = unit
        .path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "go");
    materialized && parent_is_language_root
}

pub(crate) fn is_project_anchor(unit: &ParsedUnit) -> bool {
    let root = discover_project_root(&unit.path);
    let mut files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("go"))
        .filter(|path| !path.to_string_lossy().ends_with("_test.go"))
        .collect();
    files.sort();
    files.first().is_some_and(|path| path == &unit.path)
}
