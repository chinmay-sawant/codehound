use std::collections::HashMap;

use crate::core::ParsedUnit;

/// Build an import map for a parsed unit: alias → full import path.
///
/// For an import like `import "net/http"`, the alias is `"http"` (last path
/// segment).  For `import alias "pkg/path"`, the alias is `"alias"`.
/// Blank (`_`) and dot (`.`) imports are excluded.
// ponytail: used only for distinguishing internal vs external package calls.
// Full wiring into the cross-function analysis is deferred — same-package
// calls work without it.
pub fn build_import_map(unit: &ParsedUnit) -> HashMap<String, String> {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut map = HashMap::new();

    let mut cursor = root.walk();
    walk_imports(root, &mut cursor, src, &mut map);
    map
}

fn walk_imports(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    src: &[u8],
    map: &mut HashMap<String, String>,
) {
    if node.kind() == "import_declaration" {
        collect_imports(node, src, map);
    }

    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            walk_imports(child, cursor, src, map);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn collect_imports(node: tree_sitter::Node, src: &[u8], map: &mut HashMap<String, String>) {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let n = cursor.node();
        match n.kind() {
            "import_spec" => {
                if let Some((alias, path)) = import_spec_entry(n, src) {
                    map.insert(alias, path);
                }
            }
            "import_spec_list" => {
                let mut inner = n.walk();
                if inner.goto_first_child() {
                    loop {
                        let ic = inner.node();
                        if ic.kind() == "import_spec" {
                            if let Some((alias, path)) = import_spec_entry(ic, src) {
                                map.insert(alias, path);
                            }
                        }
                        if !inner.goto_next_sibling() {
                            break;
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

fn import_spec_entry(node: tree_sitter::Node, src: &[u8]) -> Option<(String, String)> {
    let path_node = node.child_by_field_name("path")?;
    let Ok(path_text) = path_node.utf8_text(src) else {
        return None;
    };
    let path = path_text.trim_matches('"').trim_matches('`').to_string();

    // Check for explicit alias, blank import, or dot import.
    if let Some(name_node) = node.child_by_field_name("name") {
        let Ok(name) = name_node.utf8_text(src) else {
            return None;
        };
        let name = name.trim();
        match name {
            "_" | "." => return None,
            alias => return Some((alias.to_string(), path)),
        }
    }

    // Default alias: last path segment.
    let alias = path.rsplit('/').next().unwrap_or(&path).to_string();
    Some((alias, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{LanguageId, ParsedUnit};
    use std::path::PathBuf;
    use std::sync::Arc;
    fn parse_go(source: &str) -> ParsedUnit {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        let tree = parser.parse(source, None).expect("parse");
        ParsedUnit {
            language: LanguageId::Go,
            path: PathBuf::from("test.go"),
            display_path: "test.go".into(),
            source: Arc::from(source),
            tree,
            line_starts: vec![0],
            function_spans: Vec::new(),
        }
    }

    #[test]
    fn import_map_simple() {
        let unit = parse_go(r#"package main; import "net/http""#);
        let map = build_import_map(&unit);
        assert_eq!(map.get("http").map(String::as_str), Some("net/http"));
    }

    #[test]
    fn import_map_alias() {
        let unit = parse_go(r#"package main; import myhttp "net/http""#);
        let map = build_import_map(&unit);
        assert_eq!(map.get("myhttp").map(String::as_str), Some("net/http"));
    }

    #[test]
    fn import_map_block() {
        let unit = parse_go(r#"package main; import ( "fmt"; "strings"; mydb "database/sql" )"#);
        let map = build_import_map(&unit);
        assert_eq!(map.get("fmt").map(String::as_str), Some("fmt"));
        assert_eq!(map.get("strings").map(String::as_str), Some("strings"));
        assert_eq!(map.get("mydb").map(String::as_str), Some("database/sql"));
    }

    #[test]
    fn import_map_excludes_blank_and_dot() {
        let unit = parse_go(r#"package main; import ( _ "unsafe"; . "math"; "os" )"#);
        let map = build_import_map(&unit);
        assert!(!map.contains_key("_"));
        assert!(!map.contains_key("."));
        assert_eq!(map.get("os").map(String::as_str), Some("os"));
    }
}
