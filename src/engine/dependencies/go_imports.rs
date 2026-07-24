//! Go-specific dependency extraction (import-spec walk + module prefix
//! filtering).

use std::path::Path;

use tree_sitter::Node;

use super::resolve::{extensions_for, resolve_local_path};

pub(crate) fn extract(
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
                            if ic.kind() == "import_spec"
                                && let Some(path) = import_spec_path(&ic, source)
                            {
                                resolve_and_add(&path, module_prefix, project_root, out);
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
    let exts = extensions_for(crate::core::LanguageId::Go);
    if let Some(paths) = resolve_local_path(&abs, exts) {
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
    if !module_prefix.is_empty() && import_path.starts_with(module_prefix) {
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
