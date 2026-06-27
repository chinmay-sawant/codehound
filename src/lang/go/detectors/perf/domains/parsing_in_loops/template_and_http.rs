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

    let request_path = facts.source_index.has("gin.HandlerFunc")
        || facts.source_index.has("c.JSON(")
        || facts.source_index.has("c.HTML(")
        || facts.source_index.has("*gin.Context")
        || facts.source_index.has("echo.Context")
        || facts.source_index.has("http.ResponseWriter")
        || facts.source_index.has("c *gin.Context")
        || facts.source_index.has("c echo.Context");
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
    if !facts.source_index.has_any(&triggers) {
        return;
    }
    if facts.source_index.has("template.Must(parseTemplates(")
        || facts.source_index.has("var indexTmpl =")
        || facts.source_index.has("sync.Once")
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

    let request_path = facts.source_index.has("gin.HandlerFunc")
        || facts.source_index.has("c.JSON(")
        || facts.source_index.has("*gin.Context")
        || facts.source_index.has("echo.Context")
        || facts.source_index.has("http.ResponseWriter")
        || facts.source_index.has("func (");
    if !request_path {
        return;
    }

    let triggers = ["http.Client{", "&http.Client{"];
    if !facts.source_index.has_any(&triggers) {
        return;
    }
    if facts.source_index.has("var defaultClient =") || facts.source_index.has("var httpClient =") {
        return;
    }
    if facts.source_index.has("sync.Once") {
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
}

/// PERF-012: db.Prepare / db.PrepareContext on the request path.
pub(crate) fn detect_perf_12(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let request_path = facts.source_index.has("gin.HandlerFunc")
        || facts.source_index.has("c.JSON(")
        || facts.source_index.has("c.HTML(")
        || facts.source_index.has("*gin.Context")
        || facts.source_index.has("echo.Context")
        || facts.source_index.has("http.ResponseWriter")
        || facts.source_index.has("func (");
    if !request_path {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "db.Prepare" | "db.PrepareContext") {
            continue;
        }
        if !is_in_loop(call)
            && (facts.source_index.has("sync.Once")
                || facts.source_index.has("var stmtOnce")
                || facts.source_index.has("StmtOnce"))
        {
            continue;
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