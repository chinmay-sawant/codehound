//! Fact extraction for Go PERF heuristics.
//!
//! Each detector receives a [`GoPerfFacts`] summary that fuses a single
//! tree-sitter walk with a substring index. The same call / assignment facts
//! the CWE bundle uses are reused here, so the cost is one extra walk per file
//! rather than one per detector.

use std::collections::HashMap;
use std::sync::Arc;

use tree_sitter::Node;

use crate::ast::{walk_calls_and_assignments, walk_nodes};
use crate::core::ParsedUnit;

use super::source_index::PerfSourceIndex;

type SharedText = Arc<str>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: SharedText,
    pub arguments: Box<[SharedText]>,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: SharedText,
    pub expr: SharedText,
    /// Full text of the assignment node, including any compound-assignment
    /// operator (e.g. `s += strconv.Itoa(v)`). Detectors that care about the
    /// operator consult this instead of reconstructing it from `name` + `expr`.
    pub text: SharedText,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

/// Coarse classification of a variable's type based on its declaration site.
///
/// This is intentionally narrow: it only needs to tell numeric accumulators
/// (`totalDur += d`) apart from string concatenations (`s += "..."`). Unknown
/// means "could not determine" — detectors should treat Unknown as
/// permissive, not as "definitely numeric".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind {
    Numeric,
    String,
    Bytes,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoPerfFacts {
    pub calls: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    /// Single-pass substring flags for hot detector guards.
    pub source_index: PerfSourceIndex,
    /// Variable-name → coarse type, derived from `var` specs and short-var
    /// declarations in the current file. Used to suppress heuristics that
    /// would otherwise misfire on numeric accumulators (e.g. PERF-2 firing
    /// on `totalDur := 0.0` + `totalDur += d`).
    pub var_kinds: HashMap<SharedText, VarKind>,
    pub defer_starts: Vec<(usize, usize)>,
    pub go_starts: Vec<(usize, usize)>,
    pub for_ranges: Vec<(usize, usize)>,
    pub type_assertions: Vec<(usize, usize)>,
}

pub fn build_go_perf_facts(unit: &ParsedUnit) -> GoPerfFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoPerfFacts::default();
    let mut interner = SharedTextInterner::default();

    walk_calls_and_assignments(root, &mut |node| match node.kind() {
        "call_expression" | "call" => {
            record_call_fact(node, &mut facts, src, &mut interner);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment_fact(node, &mut facts, src, &mut interner);
        }
        "defer_statement" | "go_statement" | "for_statement" | "type_assertion_expression" => {
            record_perf_node(node, &mut facts);
        }
        _ => {}
    });

    // Walk `var_spec` nodes to capture variables declared with an explicit
    // type (`var x int = 5`, `var s string`, `var buf []byte`). The explicit
    // type always wins; if the spec also has an initializer it is only used
    // as a fallback (e.g. `var x = 0.0`).
    walk_nodes(root, &["var_spec"], &mut |spec| {
        collect_var_spec_kinds(spec, src, &mut facts.var_kinds, &mut interner);
    });

    facts.source_index = PerfSourceIndex::build(unit.source.as_ref());
    facts
}

pub(crate) fn record_call_fact<'a>(
    node: Node,
    facts: &mut GoPerfFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(callee) = func.utf8_text(src) else {
        return;
    };

    let arguments = node
        .child_by_field_name("arguments")
        .map(|args| extract_argument_texts(args, src, interner))
        .unwrap_or_default();

    facts.calls.push(CallFact {
        callee: interner.intern(callee),
        arguments,
        start_byte: node.start_byte(),
        enclosing_loop: enclosing_loop_start(node),
    });
}

pub(crate) fn record_assignment_fact<'a>(
    node: Node,
    facts: &mut GoPerfFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Ok(text) = node.utf8_text(src) else {
        return;
    };
    let Some((lhs, rhs)) = split_assignment(text) else {
        return;
    };
    let is_short = text.contains(":=");
    for name in extract_identifiers(lhs) {
        if name.is_empty() {
            continue;
        }
        facts.assignments.push(AssignmentFact {
            name: interner.intern(name),
            expr: interner.intern(rhs),
            text: interner.intern(text),
            start_byte: node.start_byte(),
            enclosing_loop: enclosing_loop_start(node),
        });
        if is_short && !facts.var_kinds.contains_key(name) {
            if let Some(kind) = classify_init_only(rhs) {
                facts.var_kinds.insert(interner.intern(name), kind);
            }
        }
    }
}

pub(crate) fn record_perf_node(node: Node, facts: &mut GoPerfFacts) {
    match node.kind() {
        "defer_statement" => {
            facts
                .defer_starts
                .push((node.start_byte(), node.end_byte()));
        }
        "go_statement" => {
            facts.go_starts.push((node.start_byte(), node.end_byte()));
        }
        "for_statement" => {
            facts.for_ranges.push((node.start_byte(), node.end_byte()));
        }
        "type_assertion_expression" => {
            facts
                .type_assertions
                .push((node.start_byte(), node.end_byte()));
        }
        _ => {}
    }
}

/// Returns the start byte of the nearest enclosing `for_statement`, if any.
pub(crate) fn enclosing_loop_start(node: Node) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "for_statement" {
            return Some(parent.start_byte());
        }
        current = parent;
    }
    None
}

#[derive(Default)]
pub(crate) struct SharedTextInterner<'a> {
    pub(crate) values: HashMap<&'a str, SharedText>,
}

impl<'a> SharedTextInterner<'a> {
    pub(crate) fn intern(&mut self, text: &'a str) -> SharedText {
        if let Some(existing) = self.values.get(text) {
            return Arc::clone(existing);
        }

        let shared: SharedText = Arc::from(text);
        self.values.insert(text, Arc::clone(&shared));
        shared
    }
}

pub(crate) fn extract_argument_texts<'a>(
    args_node: tree_sitter::Node,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) -> Box<[SharedText]> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(interner.intern(text.trim()));
        }
    }
    out.into_boxed_slice()
}

#[doc(hidden)]
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    // Split on the first compound assignment operator (`+=`, `-=`, `<<=`,
    // …) so the operator characters do not leak into the LHS identifier
    // (e.g. `totalDur += d` → LHS = "totalDur", not "totalDur +").
    const COMPOUND: &[&str] = &[
        "<<=", ">>=", "&^=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    ];
    for op in COMPOUND {
        if let Some(idx) = text.find(op) {
            let (lhs, rhs) = text.split_at(idx);
            return Some((lhs.trim(), rhs[op.len()..].trim()));
        }
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

#[doc(hidden)]
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

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
fn classify_init_only(init: &str) -> Option<VarKind> {
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
