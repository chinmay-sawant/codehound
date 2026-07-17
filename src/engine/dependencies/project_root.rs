//! Walk up from `start` looking for the first directory containing
//! a `.git` entry **or** a `go.mod` file (whichever is closer).
//!
//! `go.mod` is recognized so that scanning a Go module that lives
//! under a directory tree containing a stray `.git` (CI sandboxes
//! frequently have one) still resolves to the module root.

use std::path::{Path, PathBuf};

use crate::engine::path_walk::{WalkUpAction, walk_up_dirs};

/// Discover the project root by walking up from `start` for `.git` or `go.mod`.
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
