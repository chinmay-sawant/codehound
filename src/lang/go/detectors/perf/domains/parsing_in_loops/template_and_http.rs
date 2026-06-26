use super::super::super::common::is_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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
