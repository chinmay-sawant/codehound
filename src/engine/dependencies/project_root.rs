//! Walk up from `start` looking for the first directory containing
//! a `.git` entry **or** a `go.mod` file (whichever is closer).
//!
//! `go.mod` is recognized so that scanning a Go module that lives
//! under a directory tree containing a stray `.git` (CI sandboxes
//! frequently have one) still resolves to the module root.

use std::path::{Path, PathBuf};

pub fn discover_project_root(start: &Path) -> PathBuf {
    let mut current: PathBuf = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        if current.join(".git").exists() || current.join("go.mod").is_file() {
            return current;
        }
        if !current.pop() {
            return start.to_path_buf();
        }
    }
}
