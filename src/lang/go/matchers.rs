//! Go-specific AST predicates.

use tree_sitter::Node;

pub fn is_regexp_compile(node: Node, src: &[u8]) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    let text = func.utf8_text(src).unwrap_or("");
    matches!(text, "regexp.MustCompile" | "regexp.Compile")
}

pub fn is_append_call(node: Node, src: &[u8]) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    func.utf8_text(src).unwrap_or("") == "append"
}

pub fn is_make_map_call(node: Node, src: &[u8]) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    if func.utf8_text(src).unwrap_or("") != "make" {
        return false;
    }
    node.utf8_text(src).unwrap_or("").starts_with("make(map")
}

pub fn is_string_concat_assign(node: Node, src: &[u8]) -> bool {
    node.utf8_text(src).unwrap_or("").contains('+')
}
