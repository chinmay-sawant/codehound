//! Shared path/fixture helpers for Go bad-practice detectors.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use walkdir::WalkDir;

use crate::core::ParsedUnit;
use crate::engine::discover_project_root;

pub(crate) fn is_test_file(unit: &ParsedUnit) -> bool {
    unit.display_path.ends_with("_test.go")
}

pub(crate) fn is_materialized_fixture(unit: &ParsedUnit) -> bool {
    let display = unit.display_path.as_str();
    display.contains("target/codehound-fixtures/")
        || display.contains("target\\codehound-fixtures\\")
}

pub(crate) fn is_flat_materialized_fixture(unit: &ParsedUnit) -> bool {
    let display = unit.display_path.as_str();
    let materialized = display.contains("target/codehound-fixtures/")
        || display.contains("target\\codehound-fixtures\\");
    let parent_is_language_root = unit
        .path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "go");
    materialized && parent_is_language_root
}

/// True when `unit` is the lexicographically first non-test `.go` file under the
/// project root. Used so project-level rules emit once per repo, not per file.
///
/// The expensive WalkDir is memoized per project root for the process lifetime
/// (safe across Rayon workers via a mutex).
pub(crate) fn is_project_anchor(unit: &ParsedUnit) -> bool {
    let root = discover_project_root(&unit.path);
    let Some(anchor) = project_anchor_for_root(&root) else {
        return false;
    };
    anchor == unit.path
}

fn project_anchor_for_root(root: &Path) -> Option<PathBuf> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Option<PathBuf>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(root) {
        return cached.clone();
    }
    let mut files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("go"))
        .filter(|path| !path.to_string_lossy().ends_with("_test.go"))
        .collect();
    files.sort();
    let anchor = files.into_iter().next();
    guard.insert(root.to_path_buf(), anchor.clone());
    anchor
}

type ProjectTexts = Vec<(PathBuf, String)>;
type ProjectTextCache = HashMap<PathBuf, ProjectTexts>;

/// Memoized full-project `.go` text load for project-level BP rules.
pub(crate) fn read_project_texts_cached(unit: &ParsedUnit) -> ProjectTexts {
    let root = discover_project_root(&unit.path);
    static CACHE: OnceLock<Mutex<ProjectTextCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(&root) {
        return cached.clone();
    }
    let mut texts = Vec::new();
    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            texts.push((path.to_path_buf(), text));
        }
    }
    texts.sort_by(|left, right| left.0.cmp(&right.0));
    guard.insert(root, texts.clone());
    texts
}
