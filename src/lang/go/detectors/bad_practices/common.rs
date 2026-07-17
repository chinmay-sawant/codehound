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
/// project root. Uses the shared project snapshot (one WalkDir per root).
pub(crate) fn is_project_anchor(unit: &ParsedUnit) -> bool {
    let root = discover_project_root(&unit.path);
    let Some(anchor) = project_snapshot_for_root(&root).anchor else {
        return false;
    };
    anchor == unit.path
}

/// Shared project-level facts for BP-47/50/54/55 (and friends).
///
/// Built once per project root via a single WalkDir + text scan. Production
/// rules use the precomputed flags (no multi-MB clone under the mutex).
#[derive(Clone)]
pub(crate) struct ProjectSnapshot {
    /// Lexicographically first non-test `.go` path (project anchor), if any.
    pub anchor: Option<PathBuf>,
    pub has_server_start: bool,
    pub has_shutdown: bool,
    pub has_signal_handling: bool,
    pub has_public_route: bool,
    pub has_rate_limiting: bool,
    pub has_request_id: bool,
    pub has_logging: bool,
}

/// Return the memoized project snapshot for `unit`'s project root.
pub(crate) fn project_snapshot(unit: &ParsedUnit) -> ProjectSnapshot {
    let root = discover_project_root(&unit.path);
    project_snapshot_for_root(&root)
}

/// Pre-warm project snapshot for a scan root before parallel BP work.
pub(crate) fn prewarm_project_snapshot(start: &Path) {
    let root = discover_project_root(start);
    let _ = project_snapshot_for_root(&root);
}

type SnapshotCache = HashMap<PathBuf, ProjectSnapshot>;

fn snapshot_cache() -> &'static Mutex<SnapshotCache> {
    static CACHE: OnceLock<Mutex<SnapshotCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn project_snapshot_for_root(root: &Path) -> ProjectSnapshot {
    let mut guard = snapshot_cache().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(root) {
        return cached.clone();
    }
    let built = build_project_snapshot(root);
    guard.insert(root.to_path_buf(), built.clone());
    built
}

/// Directory basenames skipped when building project-level BP facts.
///
/// Without this, a single BP scan of a monorepo (or of a `.txt` fixture
/// materialized under `target/codehound-fixtures/`) walks the entire tree —
/// including Rust `target/`, `node_modules/`, and accumulated fixture dumps —
/// and can spend seconds reading irrelevant `.go` files on every CLI process.
const SKIP_PROJECT_WALK_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    "vendor",
    ".codehound-cache",
    "codehound-fixtures",
    "__pycache__",
    ".idea",
    ".vscode",
];

fn should_enter_project_dir(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
        return true;
    };
    !SKIP_PROJECT_WALK_DIRS.contains(&name)
}

fn build_project_snapshot(root: &Path) -> ProjectSnapshot {
    let mut go_files: Vec<PathBuf> = Vec::new();
    let mut has_server_start = false;
    let mut has_shutdown = false;
    let mut has_signal_handling = false;
    let mut has_public_route = false;
    let mut has_rate_limiting = false;
    let mut has_request_id = false;
    let mut has_logging = false;

    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(should_enter_project_dir);
    for entry in walker.filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go") {
            continue;
        }
        let path_buf = path.to_path_buf();
        if !path_buf.to_string_lossy().ends_with("_test.go") {
            go_files.push(path_buf);
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if !has_server_start && contains_server_start(&text) {
            has_server_start = true;
        }
        if !has_shutdown && text.contains(".Shutdown(") {
            has_shutdown = true;
        }
        if !has_signal_handling
            && (text.contains("signal.Notify(")
                || text.contains("signal.NotifyContext(")
                || text.contains("\"os/signal\""))
        {
            has_signal_handling = true;
        }
        if !has_public_route && contains_public_route(&text) {
            has_public_route = true;
        }
        if !has_rate_limiting
            && (text.contains("rate.NewLimiter(")
                || text.contains("rate.Limiter")
                || text.contains("tollbooth")
                || text.contains("httprate")
                || text.contains("Throttle("))
        {
            has_rate_limiting = true;
        }
        if !has_request_id
            && (text.contains("Request-ID")
                || text.contains("Request-Id")
                || text.contains("X-Request-ID")
                || text.contains("X-Request-Id")
                || text.contains("requestid")
                || text.contains("request_id")
                || text.contains("RequestID"))
        {
            has_request_id = true;
        }
        if !has_logging
            && (text.contains("log.") || text.contains("logger.") || text.contains("slog."))
        {
            has_logging = true;
        }
    }
    go_files.sort();
    let anchor = go_files.into_iter().next();

    ProjectSnapshot {
        anchor,
        has_server_start,
        has_shutdown,
        has_signal_handling,
        has_public_route,
        has_rate_limiting,
        has_request_id,
        has_logging,
    }
}

fn contains_server_start(text: &str) -> bool {
    text.contains("ListenAndServe(")
        || text.contains(".ListenAndServe(")
        || text.contains(".Serve(")
        || text.contains("http.Serve(")
}

fn contains_public_route(text: &str) -> bool {
    text.contains("HandleFunc(")
        || text.contains(".HandleFunc(")
        || text.contains(".Handle(")
        || text.contains(".GET(")
        || text.contains(".POST(")
        || text.contains(".PUT(")
        || text.contains(".DELETE(")
        || text.contains(".PATCH(")
}
