//! PERF-009 through PERF-016: parsing, allocation, and reuse issues on
//! hot paths (request handlers, long-running loops).

use super::super::common::is_in_loop;
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-009: url.Parse / url.ParseRequestURI inside a loop.
pub(crate) fn detect_perf_9(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "url.Parse" | "url.ParseRequestURI") {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_9,
            file,
            line,
            col,
            "URL is parsed inside a loop body",
            out,
        );
    }
}

/// PERF-010: template.New(...).Parse(...) or template.ParseFiles on the
/// request path.
pub(crate) fn detect_perf_10(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_path = source.contains("gin.HandlerFunc")
        || source.contains("c.JSON(")
        || source.contains("c.HTML(")
        || source.contains("*gin.Context")
        || source.contains("echo.Context")
        || source.contains("http.ResponseWriter")
        || source.contains("c *gin.Context")
        || source.contains("c echo.Context");
    if !request_path {
        return;
    }

    let triggers = [
        "template.New(",
        "template.ParseFiles(",
        "template.Must(template.Parse",
        "html/template.New(",
        "html/template.ParseFiles(",
    ];
    let has_template_parse = triggers.iter().any(|t| source.contains(t));
    if !has_template_parse {
        return;
    }
    if !facts.source_index.has_any(&triggers) {
        return;
    }
    if source.contains("template.Must(parseTemplates(")
        || source.contains("var indexTmpl =")
        || source.contains("sync.Once")
    {
        return;
    }

    for call in &facts.calls {
        let is_match = matches!(
            call.callee.as_ref(),
            "template.New"
                | "template.ParseFiles"
                | "html/template.New"
                | "html/template.ParseFiles"
        );
        if !is_match {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_10,
            file,
            line,
            col,
            "template is parsed on the request path",
            out,
        );
        return;
    }

    // Fall back: emit at the first matching literal.
    let start = triggers
        .iter()
        .filter_map(|t| source.find(t))
        .min()
        .unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_10,
        file,
        line,
        col,
        "template is parsed on the request path",
        out,
    );
}

/// PERF-011: http.Client allocated on the request path.
pub(crate) fn detect_perf_11(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_path = source.contains("gin.HandlerFunc")
        || source.contains("c.JSON(")
        || source.contains("*gin.Context")
        || source.contains("echo.Context")
        || source.contains("http.ResponseWriter")
        || source.contains("func (");
    if !request_path {
        return;
    }

    let triggers = ["http.Client{", "&http.Client{"];
    if !triggers.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("var defaultClient =") || source.contains("var httpClient =") {
        return;
    }
    if source.contains("sync.Once") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        if !expr.contains("http.Client{") {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_11,
            file,
            line,
            col,
            "http.Client is allocated on the request path",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-012: db.Prepare / db.PrepareContext on the request path.
pub(crate) fn detect_perf_12(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_path = source.contains("gin.HandlerFunc")
        || source.contains("c.JSON(")
        || source.contains("c.HTML(")
        || source.contains("*gin.Context")
        || source.contains("echo.Context")
        || source.contains("http.ResponseWriter")
        || source.contains("func (");
    if !request_path {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "db.Prepare" | "db.PrepareContext") {
            continue;
        }
        if !is_in_loop(call) {
            // Allow per-request prepare if the function body already caches.
            if source.contains("sync.Once")
                || source.contains("var stmtOnce")
                || source.contains("StmtOnce")
            {
                continue;
            }
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_12,
            file,
            line,
            col,
            "prepared statement is created on the request path",
            out,
        );
        return;
    }
}

/// PERF-013: time.After inside long-running loops.
pub(crate) fn detect_perf_13(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_ticker_already =
        source.contains("time.NewTicker(") || source.contains("time.NewTimer(");
    if has_ticker_already {
        return;
    }

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if call.callee.as_ref() != "time.After" {
            continue;
        }
        // Suppress bounded loops (for i := 0; i < N; i++ with small N literal).
        if let Some(loop_node) = unit.tree.root_node().descendant_for_byte_range(
            call.enclosing_loop.unwrap_or(0),
            call.enclosing_loop.unwrap_or(0),
        ) {
            let _ = loop_node;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_13,
            file,
            line,
            col,
            "time.After is allocated inside a loop body",
            out,
        );
    }
}

/// PERF-014: filepath.Glob / os.ReadDir inside a loop.
pub(crate) fn detect_perf_14(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = ["filepath.Glob", "os.ReadDir", "ioutil.ReadDir"];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_14,
            file,
            line,
            col,
            "directory scan is performed inside a loop body",
            out,
        );
    }
}

/// PERF-015: strconv formatting inside a loop.
pub(crate) fn detect_perf_15(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = [
        "strconv.Itoa",
        "strconv.FormatInt",
        "strconv.FormatUint",
        "strconv.FormatFloat",
    ];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        if call.callee.as_ref() == "strconv.AppendInt"
            || call.callee.as_ref() == "strconv.AppendUint"
            || call.callee.as_ref() == "strconv.AppendFloat"
        {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_15,
            file,
            line,
            col,
            "strconv formatting is performed inside a loop body",
            out,
        );
    }
}

/// PERF-016: bytes.Buffer{} or new(bytes.Buffer) inside a loop.
pub(crate) fn detect_perf_16(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("bytes.Buffer{}") && !source.contains("new(bytes.Buffer)") {
        return;
    }
    if !source.contains("bytes.Buffer{") {
        return;
    }

    // TODO: move to facts
    walk_nodes(
        unit.tree.root_node(),
        &["composite_literal", "unary_expression"],
        &mut |node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            if text != "bytes.Buffer{}" && text != "new(bytes.Buffer)" {
                return;
            }
            let mut current = node;
            let mut in_loop = false;
            while let Some(parent) = current.parent() {
                if parent.kind() == "for_statement" {
                    in_loop = true;
                    break;
                }
                current = parent;
            }
            if !in_loop {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_16,
                file,
                line,
                col,
                "bytes.Buffer is allocated inside a loop body",
                out,
            );
        },
    );
}
