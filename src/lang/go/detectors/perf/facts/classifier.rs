use std::collections::HashMap;

use tree_sitter::Node;

use super::types::*;

/// Walk a `var_spec` node, classify each declared name, and store the result
/// in `kinds`. Existing entries are kept (first declaration wins) so that an
/// initializer-based classification from an earlier `:=` isn't overwritten by
/// a later `=` reassignment.
pub(crate) fn collect_var_spec_kinds<'a>(
    spec: Node,
    src: &'a [u8],
    kinds: &mut HashMap<SharedText, VarKind>,
    interner: &mut SharedTextInterner<'a>,
) {
    let type_text = spec
        .child_by_field_name("type")
        .and_then(|n| n.utf8_text(src).ok());
    let init_text = spec
        .child_by_field_name("value")
        .and_then(|n| n.utf8_text(src).ok());

    let mut names: Vec<&str> = Vec::new();
    let mut cursor = spec.walk();
    for name_node in spec.children_by_field_name("name", &mut cursor) {
        if name_node.kind() != "identifier" {
            continue;
        }
        if let Ok(name) = name_node.utf8_text(src) {
            if !name.is_empty() {
                names.push(name);
            }
        }
    }

    for name in names {
        if kinds.contains_key(name) {
            continue;
        }
        if let Some(kind) = classify_var_kind(type_text, init_text) {
            kinds.insert(interner.intern(name), kind);
        }
    }
}

/// Classify a variable from its declaration: explicit type wins, otherwise
/// fall back to inferring from the initializer expression.
fn classify_var_kind(type_text: Option<&str>, init_text: Option<&str>) -> Option<VarKind> {
    if let Some(t) = type_text.map(str::trim) {
        return match t {
            "int" | "int8" | "int16" | "int32" | "int64" | "uint" | "uint8" | "uint16"
            | "uint32" | "uint64" | "uintptr" | "float32" | "float64" | "complex64"
            | "complex128" | "byte" | "rune" => Some(VarKind::Numeric),
            "string" => Some(VarKind::String),
            _ if t.starts_with("[]byte") => Some(VarKind::Bytes),
            _ => None,
        };
    }
    classify_init_only(init_text.unwrap_or(""))
}

/// Classify a variable from the initializer of a short-var declaration only.
/// Returns `None` when the initializer is a non-literal expression
/// (function call, type conversion, arithmetic) because we can't tell what
/// type the binding will have.
pub(super) fn classify_init_only(init: &str) -> Option<VarKind> {
    let init = init.trim();
    if init.is_empty() {
        return None;
    }
    // Multi-value initializer: `a, b := 1, 2`. All values must agree.
    let mut result: Option<VarKind> = None;
    for part in init.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let kind = classify_single_expr(part)?;
        match result {
            None => result = Some(kind),
            Some(prev) if prev == kind => {}
            Some(_) => return None,
        }
    }
    result
}

fn classify_single_expr(expr: &str) -> Option<VarKind> {
    let first = expr.chars().next()?;
    match first {
        '"' | '`' => return Some(VarKind::String),
        '\'' => return Some(VarKind::Numeric),
        _ => {}
    }
    let body = expr
        .strip_prefix('+')
        .or_else(|| expr.strip_prefix('-'))
        .unwrap_or(expr);
    if is_numeric_literal_text(body) {
        return Some(VarKind::Numeric);
    }
    if let Some(rest) = body.strip_suffix('i') {
        if is_numeric_literal_text(rest) {
            return Some(VarKind::Numeric);
        }
    }
    None
}

/// True for integer (`0`, `0xFF`, `0o7`, `0b101`), floating-point
/// (`0.0`, `3.14`, `1e10`), and imaginary (`1i`, `2.5i`) literal bodies
/// after any leading sign has been stripped. Go allows `_` as a digit
/// separator (`1_000_000`).
fn is_numeric_literal_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'0' && s.len() >= 2 {
        match bytes[1] {
            b'x' | b'X' | b'o' | b'O' | b'b' | b'B' => {
                return s[2..].chars().all(|c| c.is_ascii_hexdigit() || c == '_');
            }
            _ => {}
        }
    }
    let mut has_dot = false;
    let mut has_exp = false;
    for c in s.chars() {
        match c {
            '0'..='9' | '_' => {}
            '.' if !has_dot && !has_exp => has_dot = true,
            'e' | 'E' if !has_exp => has_exp = true,
            _ => return false,
        }
    }
    true
}
