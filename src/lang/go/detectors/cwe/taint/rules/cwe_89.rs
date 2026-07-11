//! Detect CWE-89 (SQL Injection) via taint flow.

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
fn is_parameterized_query(source: &str, range: &std::ops::Range<usize>) -> bool {
    let call = &source[range.start..range.end];
    let body = match call.find('(') {
        Some(p) => &call[p + 1..],
        None => return false,
    };
    // Walk to find the end of the first top-level argument.
    let mut depth = 0;
    let mut end = 0;
    for (i, ch) in body.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                end = i;
                break;
            }
            ')' => depth -= 1,
            ',' if depth == 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let first = body[..end].trim();
    // A raw string literal as first argument → parameterized query
    first.starts_with('"') || first.starts_with('`')
}
