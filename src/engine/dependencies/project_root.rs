//! Walk up from `start` looking for the first directory containing
//! a `.git` entry **or** a `go.mod` file (whichever is closer).
//!
//! `go.mod` is recognized so that scanning a Go module that lives
//! under a directory tree containing a stray `.git` (CI sandboxes
//! frequently have one) still resolves to the module root.
//!
//! Dependency extraction uses [`dependency_base_root`], which prefers a
//! module marker and otherwise the requested scan root — never an
//! unrelated parent VCS root alone.

use std::path::{Path, PathBuf};

use crate::engine::path_walk::{WalkUpAction, walk_up_dirs};

/// Discover the project root by walking up from `start` for `.git` or `go.mod`.
///
/// Used for pack-level project prep (e.g. BP snapshots). For cache dependency
/// extraction, prefer [`dependency_base_root`].
pub fn discover_project_root(start: &Path) -> PathBuf {
    walk_up_dirs(start, |current| {
        if current.join(".git").exists() || current.join("go.mod").is_file() {
            WalkUpAction::Found(current.to_path_buf())
        } else {
            WalkUpAction::Continue
        }
    })
    .unwrap_or_else(|| start.to_path_buf())
}

/// Base path for language-neutral dependency extraction and cache cascade keys.
///
/// Prefers a directory containing a module marker (`go.mod`) when walking up
/// from `start`. If none is found, falls back to the **requested scan root**
/// (the path itself, or its parent when `start` is a file).
///
/// Deliberately does **not** treat a bare parent `.git` as the dependency base:
/// resolving `import "pkg/db"` against an unrelated VCS parent (common in CI
/// sandboxes) yields paths outside the scanned tree and breaks cascade.
pub fn dependency_base_root(start: &Path) -> PathBuf {
    let scan_root = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };
    walk_up_dirs(start, |current| {
        if current.join("go.mod").is_file() {
            WalkUpAction::Found(current.to_path_buf())
        } else {
            WalkUpAction::Continue
        }
    })
    .unwrap_or(scan_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("codehound-dep-root-{label}-{unique}"));
        std::fs::create_dir_all(&path).expect("mkdir");
        path
    }

    #[test]
    fn dependency_base_prefers_go_mod_over_parent_git() {
        let outer = temp("outer-git");
        std::fs::create_dir_all(outer.join(".git")).unwrap();
        let module = outer.join("module");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(module.join("go.mod"), "module example.com/m\n").unwrap();
        assert_eq!(dependency_base_root(&module), module);
        let _ = std::fs::remove_dir_all(outer);
    }

    #[test]
    fn dependency_base_falls_back_to_scan_root_not_parent_git() {
        let outer = temp("outer-git-only");
        std::fs::create_dir_all(outer.join(".git")).unwrap();
        let project = outer.join("project");
        std::fs::create_dir_all(&project).unwrap();
        assert_eq!(dependency_base_root(&project), project);
        // VCS discovery still walks to parent .git for pack prep.
        assert_eq!(discover_project_root(&project), outer);
        let _ = std::fs::remove_dir_all(outer);
    }
}
