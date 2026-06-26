//! Python-specific dependency extraction (import-statement walk + relative
//! import handling).

use std::path::Path;

use tree_sitter::Node;

use super::entry::{extensions, resolve_local_path};

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

fn walk(node: &Node, source: &str, project_root: &Path, source_dir: &str, out: &mut Vec<String>) {
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
    let exts = extensions(crate::core::LanguageId::Python);
    if let Some(paths) = resolve_local_path(abs, exts) {
        for p in paths {
            out.push(p.display().to_string().replace('\\', "/"));
        }
    }
}
