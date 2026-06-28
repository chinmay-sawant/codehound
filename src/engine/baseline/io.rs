//! Baseline file discovery and timestamp helpers.

use std::path::{Path, PathBuf};

pub use crate::engine::time::iso8601_utc_now;

pub const BASELINE_FILE_NAME: &str = ".slopguard-baseline.json";

pub fn discover_baseline(cwd: &Path) -> Option<PathBuf> {
    let mut current = if cwd.is_file() {
        cwd.parent()?.to_path_buf()
    } else {
        cwd.to_path_buf()
    };

    loop {
        let candidate = current.join(BASELINE_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if current.join(".git").is_dir() {
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}
