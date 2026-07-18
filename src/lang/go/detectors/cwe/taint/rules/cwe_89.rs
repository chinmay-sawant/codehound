//! Detect CWE-89 (SQL Injection) via taint flow.

use std::ops::Range;

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_89;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};
use super::evidence::source_info;

pub fn detect_cwe_89_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::SQLQuery,
        &[SanitizerKind::SQL],
    );

    for path in paths {
        if path.sanitized {
            continue;
        }
        let Some(TaintNode::Sink {
            function: sink_fn,
            byte_range: sink_range,
            ..
        }) = graph.nodes.get(path.sink_id)
        else {
            continue;
        };

        // Parameterized queries (literal SQL string as first arg) are treated
        // as safe. This is a *heuristic*, not full SQLi analysis — GORM/sqlx
        // string-concat shapes still fire when the SQL arg is dynamic.
        // Upgrade: trace which argument carries the taint via edge labels.
        if is_parameterized_query(source, sink_range) {
            continue;
        }

        // Same-function Prepare/PrepareContext → same *Stmt binding used at
        // Query/Exec with a *literal* Prepare SQL string. Not a global
        // sanitizer: dynamic Prepare and rebinding still fire.
        if is_prepared_stmt_parameterized(sink_fn.as_ref(), sink_range, facts) {
            continue;
        }

        let (line, col) = unit.line_col(sink_range.start);
        let at = out.len();
        emit::push_finding_with_evidence(
            &META_CWE_89,
            file,
            line,
            col,
            "user-controlled input reaches an SQL execution sink (heuristic; not full SQLi coverage)",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo::new("SQLQuery", sink_fn.to_string()),
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
        for f in out.iter_mut().skip(at) {
            f.confidence = Some(0.7);
        }
    }
}

/// Heuristic: if the first argument of the SQL call is a raw string literal,
/// the query uses parameterized arguments (safe).
fn is_parameterized_query(source: &str, range: &Range<usize>) -> bool {
    let call = &source[range.start..range.end];
    let body = match call.find('(') {
        Some(p) => &call[p + 1..],
        None => return false,
    };
    match nth_top_level_arg(body, 0) {
        Some(first) => is_pure_string_literal(first),
        None => false,
    }
}

/// True when `recv.Query`/`Exec` (or *Context forms) is proven to use a same-
/// function binding of `recv` from `Prepare`/`PrepareContext` with a literal
/// SQL string and no later reassignment of `recv`.
fn is_prepared_stmt_parameterized(
    sink_fn: &str,
    sink_range: &Range<usize>,
    facts: &GoUnitFacts,
) -> bool {
    let Some(receiver) = simple_sql_stmt_receiver(sink_fn) else {
        return false;
    };

    let fn_range = facts
        .taint
        .function_ranges
        .values()
        .find(|r| r.start <= sink_range.start && sink_range.end <= r.end)
        .cloned();

    // Latest write to `receiver` before the sink, restricted to the enclosing
    // function when ranges are known.
    let mut latest: Option<&crate::lang::go::detectors::cwe::taint::AssignmentDetail> = None;
    for assign in &facts.taint.assignments {
        if assign.lhs.as_ref() != receiver {
            continue;
        }
        if assign.byte_range.start >= sink_range.start {
            continue;
        }
        if let Some(ref fr) = fn_range {
            if assign.byte_range.start < fr.start || assign.byte_range.start >= fr.end {
                continue;
            }
        }
        if latest.is_none_or(|prev| assign.byte_range.start > prev.byte_range.start) {
            latest = Some(assign);
        }
    }

    let Some(assign) = latest else {
        return false;
    };
    prepare_rhs_has_literal_sql(assign.rhs_text.as_ref())
}

/// `stmt.Query` / `stmt.ExecContext` → `Some("stmt")` for simple receivers only.
fn simple_sql_stmt_receiver(sink_fn: &str) -> Option<&str> {
    let (recv, method) = sink_fn.rsplit_once('.')?;
    if recv.is_empty() || recv.contains('.') || recv.contains('(') || recv.contains('[') {
        return None;
    }
    match method {
        "Query" | "Exec" | "QueryRow" | "QueryContext" | "ExecContext" | "QueryRowContext" => {
            Some(recv)
        }
        _ => None,
    }
}

/// RHS looks like `db.Prepare("…")` or `db.PrepareContext(ctx, "…")` with a
/// literal SQL string (not a dynamic expression).
fn prepare_rhs_has_literal_sql(rhs: &str) -> bool {
    const PREPARE_CTX: &str = ".PrepareContext(";
    const PREPARE: &str = ".Prepare(";

    let (after_open, sql_arg_index) = if let Some(i) = rhs.find(PREPARE_CTX) {
        (&rhs[i + PREPARE_CTX.len()..], 1usize)
    } else if let Some(i) = rhs.find(PREPARE) {
        // `.Prepare(` is a prefix of `.PrepareContext(` — Context already handled.
        (&rhs[i + PREPARE.len()..], 0usize)
    } else {
        return false;
    };

    match nth_top_level_arg(after_open, sql_arg_index) {
        Some(arg) => is_pure_string_literal(arg),
        None => false,
    }
}

/// True when `expr` is exactly one Go string literal (interpreted or raw), not
/// a concatenation or other expression that merely starts with a quote.
fn is_pure_string_literal(expr: &str) -> bool {
    let t = expr.trim();
    if t.starts_with('"') {
        return match end_of_interpreted_string(t) {
            Some(end) => t[end..].trim().is_empty(),
            None => false,
        };
    }
    if t.starts_with('`') {
        let bytes = t.as_bytes();
        let mut i = 1;
        while i < bytes.len() {
            if bytes[i] == b'`' {
                return t[i + 1..].trim().is_empty();
            }
            i += 1;
        }
        return false;
    }
    false
}

/// Byte index just past a Go interpreted string starting at `s[0] == '"'`.
fn end_of_interpreted_string(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first().copied() != Some(b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2; // skip escaped char (good enough for arg-boundary check)
            }
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Return the `n`th top-level argument text from a call body that starts just
/// after the opening `(` (may include trailing `)` and further source).
///
/// Skips commas and parens that appear inside Go string / raw-string literals
/// so SQL text like `"SELECT id, name FROM t"` is one argument.
fn nth_top_level_arg(body: &str, n: usize) -> Option<&str> {
    let bytes = body.as_bytes();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut idx = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' if depth >= 0 => {
                // Interpreted string — advance to closing unescaped quote.
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i = (i + 2).min(bytes.len()),
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                continue;
            }
            b'`' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'`' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                if depth == 0 {
                    if idx != n {
                        return None;
                    }
                    return Some(&body[start..i]);
                }
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => {
                if idx == n {
                    return Some(&body[start..i]);
                }
                idx += 1;
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::go::detectors::cwe::facts::{
        FactBuildOpts, build_go_unit_facts_with, build_taint_graph_for_facts,
    };

    fn findings_for(source: &str) -> Vec<Finding> {
        let unit = crate::lang::parser::parse_go(source).expect("valid Go");
        let mut facts = build_go_unit_facts_with(&unit, FactBuildOpts::TAINT);
        build_taint_graph_for_facts(&mut facts);
        let mut out = Vec::new();
        detect_cwe_89_taint(&unit, &facts, &mut out);
        out
    }

    #[test]
    fn nth_top_level_arg_splits_prepare_context() {
        let body = r#"ctx, "SELECT id FROM t WHERE id = ?")"#;
        assert_eq!(
            nth_top_level_arg(body, 1).map(str::trim),
            Some(r#""SELECT id FROM t WHERE id = ?""#)
        );
        // Commas inside the SQL string are not argument separators.
        let body2 = r#""SELECT id, name FROM users WHERE name = ?")"#;
        assert_eq!(
            nth_top_level_arg(body2, 0).map(str::trim),
            Some(r#""SELECT id, name FROM users WHERE name = ?""#)
        );
    }

    #[test]
    fn prepare_rhs_literal_and_dynamic() {
        assert!(prepare_rhs_has_literal_sql(
            r#"db.Prepare("SELECT id FROM users WHERE name = ?")"#
        ));
        assert!(prepare_rhs_has_literal_sql(
            r#"db.PrepareContext(ctx, "SELECT id FROM users WHERE name = ?")"#
        ));
        assert!(!prepare_rhs_has_literal_sql(
            r#"db.Prepare("SELECT " + name)"#
        ));
        assert!(!prepare_rhs_has_literal_sql(r#"db.Prepare(query)"#));
        assert!(!prepare_rhs_has_literal_sql(r#"makeStmt(db)"#));
    }

    #[test]
    fn literal_prepare_same_var_query_is_silent() {
        let source = r#"package main
import (
    "database/sql"
    "net/http"
)
func Lookup(db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    stmt, err := db.Prepare("SELECT id FROM users WHERE name = ?")
    if err != nil { return }
    rows, err := stmt.Query(name)
    _ = rows
}
"#;
        let findings = findings_for(source);
        assert!(
            findings.is_empty(),
            "literal Prepare + stmt.Query should be silent, got {findings:?}"
        );
    }

    #[test]
    fn prepare_context_same_var_is_silent() {
        let source = r#"package main
import (
    "context"
    "database/sql"
    "net/http"
)
func Lookup(ctx context.Context, db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    stmt, err := db.PrepareContext(ctx, "SELECT id FROM users WHERE name = ?")
    if err != nil { return }
    rows, err := stmt.QueryContext(ctx, name)
    _ = rows
}
"#;
        let findings = findings_for(source);
        assert!(
            findings.is_empty(),
            "PrepareContext + QueryContext should be silent, got {findings:?}"
        );
    }

    #[test]
    fn string_concat_query_still_fires() {
        let source = r#"package main
import (
    "database/sql"
    "net/http"
)
func Lookup(db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    q := "SELECT * FROM users WHERE name = '" + name + "'"
    rows, err := db.Query(q)
    _ = rows
    _ = err
}
"#;
        let findings = findings_for(source);
        assert!(
            !findings.is_empty(),
            "string-concat Query must still fire CWE-89"
        );
    }

    #[test]
    fn rebind_after_prepare_still_fires() {
        let source = r#"package main
import (
    "database/sql"
    "net/http"
)
func Lookup(db *sql.DB, r *http.Request, other *sql.Stmt) {
    name := r.URL.Query().Get("name")
    stmt, err := db.Prepare("SELECT id FROM users WHERE name = ?")
    if err != nil { return }
    stmt = other
    rows, err := stmt.Query(name)
    _ = rows
}
"#;
        let findings = findings_for(source);
        assert!(
            !findings.is_empty(),
            "rebound stmt must not be treated as prepared, got empty findings"
        );
    }

    #[test]
    fn dynamic_prepare_sql_does_not_suppress() {
        let source = r#"package main
import (
    "database/sql"
    "net/http"
)
func Lookup(db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    q := "SELECT id FROM users WHERE name = '" + name + "'"
    stmt, err := db.Prepare(q)
    if err != nil { return }
    // Bound-arg path: without literal-Prepare proof we must not suppress.
    rows, err := stmt.Query(name)
    _ = rows
}
"#;
        let findings = findings_for(source);
        assert!(
            !findings.is_empty(),
            "dynamic Prepare SQL must not silence stmt.Query, got empty"
        );
    }

    #[test]
    fn fixture_prepare_same_var_source_is_silent() {
        let source = include_str!(
            "../../../../../../../tests/fixtures/go/taint/CWE-89-prepare-same-var-safe.txt"
        );
        let body = source.split("---\n").nth(1).expect("fixture body");
        let findings = findings_for(body);
        assert!(
            findings.is_empty(),
            "fixture prepare same-var should be silent: {findings:?}"
        );
    }
}
