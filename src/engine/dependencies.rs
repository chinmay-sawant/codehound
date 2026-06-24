//! Dependency extraction for the incremental analysis cache (P2.3
//! Phase 3.2). The cache stores per-file `dependencies: Vec<String>`
//! so that an edit to an upstream file can invalidate every
//! downstream cache entry.
//!
//! Two strategies are implemented:
//!
//! - **Go** ([`go`]): every `import_spec` whose path begins with the
//!   project module prefix (e.g. `github.com/foo/bar`) is mapped to a
//!   local path. If the path resolves to a `.go` file, that file is a
//!   dependency. If it resolves to a directory, **every** `.go` file
//!   in that directory is a dependency. Stdlib and third-party imports
//!   are skipped — they never invalidate.
//! - **Python** ([`python`]): every `import_statement` /
//!   `import_from_statement` is mapped to a `.py` file (or
//!   `__init__.py` for packages) when it can be resolved to a path
//!   inside the project. Relative imports are resolved against the
//!   source file's package directory.
//!
//! Only local file paths are returned; external modules are dropped
//! because they are immutable from the project's perspective and so
//! would never trigger a cache invalidation.
//!
//! Both functions return paths **relative to `project_root`**, using
//! forward slashes, so the result is comparable with the keys stored
//! in [`CacheManifest`](crate::engine::cache::CacheManifest) and the
//! `display_path` used by [`crate::engine::walk`].

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::{LanguageId, ParsedUnit};

/// File extensions scanned for each supported language.
fn extensions_for(lang: LanguageId) -> &'static [&'static str] {
    match lang {
        LanguageId::Go => &["go"],
        LanguageId::Python => &["py"],
        LanguageId::TypeScript => &["ts", "tsx", "js", "jsx"],
    }
}

/// Extract the list of project-local files that `unit` imports
/// (directly or, for Go directory imports, transitively at the
/// directory level).
///
/// `project_root` is used to resolve module-style imports to file
/// paths. The result is **absolute** paths, which lets the caller
/// store them in [`FileCacheMeta::dependencies`] and match them
/// directly against manifest keys (also absolute). `module_prefix`
/// is the Go module name read from `go.mod` (e.g.
/// `github.com/foo/bar`); it is the prefix that distinguishes local
/// imports from stdlib / third-party. `None` disables Go
/// dependency extraction — Python still works.
pub fn extract_dependencies(
    unit: &ParsedUnit,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match unit.language {
        LanguageId::Go => {
            if let Some(prefix) = module_prefix {
                go::extract(
                    &unit.tree.root_node(),
                    &unit.source,
                    project_root,
                    prefix,
                    &mut out,
                );
            }
        }
        LanguageId::Python => {
            python::extract(
                &unit.tree.root_node(),
                &unit.source,
                project_root,
                &unit.display_path,
                &mut out,
            );
        }
        LanguageId::TypeScript => {}
    }
    out.sort();
    out.dedup();
    out
}

/// Parse the `module` directive from a `go.mod` file. Returns the
/// trimmed module name on success, `None` when the file is missing,
/// unreadable, or does not contain a `module` directive.
pub fn go_module_prefix(project_root: &Path) -> Option<String> {
    let path = project_root.join("go.mod");
    let text = fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Walk up from `start` looking for the first directory containing
/// a `.git` entry **or** a `go.mod` file (whichever is closer).
/// Returns `start` itself when neither marker is found in the
/// chain.
///
/// `go.mod` is recognized so that scanning a Go module that lives
/// under a directory tree containing a stray `.git` (CI sandboxes
/// frequently have one) still resolves to the module root.
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

// ---- Go -----------------------------------------------------------------

mod go {
    use std::fs;
    use std::path::{Path, PathBuf};

    use tree_sitter::Node;

    use super::extensions_for;

    pub(super) fn extract(
        root: &Node,
        source: &str,
        project_root: &Path,
        module_prefix: &str,
        out: &mut Vec<String>,
    ) {
        let prefix = module_prefix.trim_end_matches('/');
        walk_imports(root, source, prefix, project_root, out);
    }

    fn walk_imports(
        node: &Node,
        source: &str,
        module_prefix: &str,
        project_root: &Path,
        out: &mut Vec<String>,
    ) {
        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            if n.kind() == "import_declaration" {
                collect_from_import_declaration(&n, source, module_prefix, project_root, out);
            }
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    fn collect_from_import_declaration(
        node: &Node,
        source: &str,
        module_prefix: &str,
        project_root: &Path,
        out: &mut Vec<String>,
    ) {
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return;
        }
        loop {
            let n = cursor.node();
            match n.kind() {
                "import_spec" | "import_spec_list" => {
                    if n.kind() == "import_spec" {
                        if let Some(path) = import_spec_path(&n, source) {
                            resolve_and_add(&path, module_prefix, project_root, out);
                        }
                    } else {
                        let mut inner = n.walk();
                        if inner.goto_first_child() {
                            loop {
                                let ic = inner.node();
                                if ic.kind() == "import_spec" {
                                    if let Some(path) = import_spec_path(&ic, source) {
                                        resolve_and_add(&path, module_prefix, project_root, out);
                                    }
                                }
                                if !inner.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    /// Extract the import path string from an `import_spec` node.
    fn import_spec_path(spec: &Node, source: &str) -> Option<String> {
        let path_node = spec.child_by_field_name("path")?;
        let text = path_node.utf8_text(source.as_bytes()).ok()?;
        // Strip surrounding quotes (interpreted_string_literal and
        // raw_string_literal both include them).
        let trimmed = text.trim_matches('"').trim_matches('`');
        Some(trimmed.to_string())
    }

    /// Map an import path to an absolute file path (or multiple
    /// files, for directory imports). Pushes the result(s) into
    /// `out` when the import is local.
    fn resolve_and_add(
        import_path: &str,
        module_prefix: &str,
        project_root: &Path,
        out: &mut Vec<String>,
    ) {
        if !is_local_import(import_path, module_prefix) {
            return;
        }
        let local = import_path
            .strip_prefix(module_prefix)
            .unwrap_or(import_path)
            .trim_start_matches('/');
        if local.is_empty() {
            return;
        }
        let abs = project_root.join(local);
        let extensions = extensions_for(crate::core::LanguageId::Go);
        if let Some(paths) = resolve_local_path(&abs, extensions) {
            for p in paths {
                out.push(p.display().to_string().replace('\\', "/"));
            }
        }
    }

    /// Local imports start with the module prefix. Stdlib packages
    /// (e.g. `fmt`, `net/http`) have no `/` in the first segment
    /// and a known short name; third-party imports contain a `.` in
    /// the first segment (e.g. `github.com/...`).
    fn is_local_import(import_path: &str, module_prefix: &str) -> bool {
        if import_path.starts_with(module_prefix) {
            return true;
        }
        // go.mod-less projects: any path containing a `/` is treated
        // as a potential local path; a path with no `/` is a single
        // package name (stdlib or local). We can't tell the
        // difference without module context, so be conservative and
        // assume single-segment paths are stdlib.
        if !import_path.contains('/') {
            return false;
        }
        // Path with a `/` but a different module prefix: still
        // probably local (nested directories under a non-module
        // project). Try the resolve.
        !import_path.contains('.')
    }

    fn resolve_local_path(abs: &Path, extensions: &[&str]) -> Option<Vec<PathBuf>> {
        if abs.is_file() {
            return Some(vec![abs.to_path_buf()]);
        }
        if abs.is_dir() {
            let mut out = Vec::new();
            visit_dir(abs, extensions, &mut out);
            if out.is_empty() { None } else { Some(out) }
        } else {
            None
        }
    }

    fn visit_dir(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip vendored / test-only directories to avoid
                // polluting the dependency graph. We still recurse
                // into the rest of the tree.
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "vendor" | "node_modules" | ".git") {
                    continue;
                }
                visit_dir(&path, extensions, out);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext) {
                    out.push(path);
                }
            }
        }
    }
}

// ---- Python -------------------------------------------------------------

mod python {
    use std::path::Path;

    use tree_sitter::Node;

    use super::extensions_for;

    pub(super) fn extract(
        root: &Node,
        source: &str,
        project_root: &Path,
        source_rel_path: &str,
        out: &mut Vec<String>,
    ) {
        let source_dir = source_rel_path
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default();
        walk(root, source, project_root, &source_dir, out);
    }

    fn walk(
        node: &Node,
        source: &str,
        project_root: &Path,
        source_dir: &str,
        out: &mut Vec<String>,
    ) {
        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            match n.kind() {
                "import_statement" | "future_import_statement" => {
                    collect_import(&n, source, project_root, source_dir, out);
                }
                "import_from_statement" => {
                    collect_import_from(&n, source, project_root, source_dir, out);
                }
                _ => {}
            }
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    fn collect_import(
        node: &Node,
        source: &str,
        project_root: &Path,
        source_dir: &str,
        out: &mut Vec<String>,
    ) {
        // `import_statement` and `future_import_statement` have a
        // `name` field that may be `dotted_name` (e.g. `import x.y`)
        // or `aliased_import` (e.g. `import x.y as z`). Walk direct
        // children and collect whichever type matches.
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return;
        }
        loop {
            let n = cursor.node();
            let text = match n.kind() {
                "dotted_name" => n.utf8_text(source.as_bytes()).ok().map(str::to_string),
                "aliased_import" => n
                    .child_by_field_name("name")
                    .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                    .map(str::to_string),
                _ => None,
            };
            if let Some(name) = text {
                resolve_module(&name, project_root, source_dir, out);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn collect_import_from(
        node: &Node,
        source: &str,
        project_root: &Path,
        source_dir: &str,
        out: &mut Vec<String>,
    ) {
        // Two cases:
        //   `from pkg.x.y import name`  ->  module_name field is a
        //                                   dotted_name (absolute) or a
        //                                   relative_import (starts with .)
        //   `from . import name`        ->  module_name field is a
        //                                   relative_import with no dotted_name child
        let module_node = match node.child_by_field_name("module_name") {
            Some(n) => n,
            None => return,
        };
        match module_node.kind() {
            "dotted_name" => {
                if let Ok(text) = module_node.utf8_text(source.as_bytes()) {
                    resolve_module(text, project_root, source_dir, out);
                }
            }
            "relative_import" => {
                let (dots, rest) = split_relative(&module_node, source);
                resolve_relative(&dots, rest.as_deref(), project_root, source_dir, out);
            }
            _ => {}
        }
    }

    fn split_relative(node: &Node, source: &str) -> (usize, Option<String>) {
        let mut dots = 0usize;
        let mut rest: Option<String> = None;
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return (dots, rest);
        }
        loop {
            let n = cursor.node();
            if n.kind() == "import_prefix" {
                if let Ok(text) = n.utf8_text(source.as_bytes()) {
                    dots = text.chars().filter(|c| *c == '.').count();
                }
            } else if n.kind() == "dotted_name" {
                if let Ok(text) = n.utf8_text(source.as_bytes()) {
                    rest = Some(text.to_string());
                }
            } else if n.kind() == "wildcard_import" {
                rest = Some(String::new());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        (dots, rest)
    }

    /// Resolve an absolute module name (e.g. `pkg.utils`) to a
    /// project-relative file path. Drops stdlib and third-party
    /// imports.
    fn resolve_module(name: &str, project_root: &Path, source_dir: &str, out: &mut Vec<String>) {
        if !is_local_module(name, project_root) {
            return;
        }
        let abs = project_root.join(name.replace('.', "/"));
        try_resolve_py(&abs, project_root, out);
        // Source dir is unused for absolute imports but is part of
        // the signature for symmetry with relative imports.
        let _ = source_dir;
    }

    fn resolve_relative(
        dots: &usize,
        rest: Option<&str>,
        project_root: &Path,
        source_dir: &str,
        out: &mut Vec<String>,
    ) {
        if *dots == 0 {
            return;
        }
        let mut dir = std::path::PathBuf::from(source_dir.replace('\\', "/"));
        // Walk up `dots - 1` levels; a single dot means "current
        // package".
        for _ in 0..(*dots).saturating_sub(1) {
            if !dir.pop() {
                return;
            }
        }
        let target = if let Some(rest) = rest {
            if rest.is_empty() {
                dir
            } else {
                dir.join(rest.replace('.', "/"))
            }
        } else {
            dir
        };
        let abs = project_root.join(target);
        try_resolve_py(&abs, project_root, out);
    }

    /// Walk up from `name`'s first segment to find a directory that
    /// exists inside `project_root`. This is a cheap proxy for
    /// "local module" — if the top-level package directory exists
    /// locally, the whole dotted path is considered local.
    fn is_local_module(name: &str, project_root: &Path) -> bool {
        if let Some((head, _)) = name.split_once('.') {
            project_root.join(head).is_dir()
        } else {
            project_root.join(name).exists()
        }
    }

    fn try_resolve_py(abs: &Path, _project_root: &Path, out: &mut Vec<String>) {
        let extensions = extensions_for(crate::core::LanguageId::Python);
        if let Some(paths) = super::resolve_local_path(abs, extensions) {
            for p in paths {
                out.push(p.display().to_string().replace('\\', "/"));
            }
        }
    }
}

// ---- Shared helpers -----------------------------------------------------

/// Resolve `abs` to one or more concrete files. Returns `Some(vec)`
/// when at least one matching file exists, `None` otherwise.
fn resolve_local_path(abs: &Path, extensions: &[&str]) -> Option<Vec<PathBuf>> {
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

fn visit_dir(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_module_prefix_parses_simple_directive() {
        let tmp = tempfile_root("go-mod-prefix");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("go.mod"), "module github.com/foo/bar\n\ngo 1.22\n").unwrap();
        assert_eq!(
            go_module_prefix(&tmp),
            Some("github.com/foo/bar".to_string())
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn go_module_prefix_returns_none_when_missing() {
        let tmp = tempfile_root("go-mod-missing");
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(go_module_prefix(&tmp), None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    fn tempfile_root(label: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("slopguard-deps-{label}-{unique}"))
    }
}
