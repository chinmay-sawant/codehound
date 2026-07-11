//! Shared `resolve_local_path` + `visit_dir` helpers used by the Go and
//! Python dependency extractors.

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::LanguageId;

/// File extensions scanned for each supported language.
pub(crate) fn extensions_for(lang: LanguageId) -> &'static [&'static str] {
    match lang {
        LanguageId::Go => &["go"],
        LanguageId::Python => &["py"],
    }
}

/// Resolve `abs` to one or more concrete files. Returns `Some(vec)`
/// when at least one matching file exists, `None` otherwise.
pub(super) fn resolve_local_path(abs: &Path, extensions: &[&str]) -> Option<Vec<PathBuf>> {
    if abs.is_file() {
        return Some(vec![abs.to_path_buf()]);
    }
    if abs.is_dir() {
        let mut out = Vec::new();
        // Package marker: prefer __init__.py in the directory itself,
        // then recurse for subpackages.
        let init = abs.join("__init__.py");
        if init.is_file() {
            out.push(init);
        }
        visit_dir(abs, extensions, &mut out);
        if out.is_empty() { None } else { Some(out) }
    } else {
        None
    }
}

pub(super) fn visit_dir(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "vendor" | "node_modules" | ".git" | "__pycache__") {
                continue;
            }
            // Subpackage: include its __init__.py if it has one.
            let init = path.join("__init__.py");
            if init.is_file() {
                out.push(init);
            }
            visit_dir(&path, extensions, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                out.push(path);
            }
        }
    }
}
