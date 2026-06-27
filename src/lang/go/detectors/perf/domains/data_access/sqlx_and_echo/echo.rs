use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_86(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has("echo.Context") {
        return;
    }
    let needle = if facts.source_index.has("c.JSON(") {
        "c.JSON("
    } else if facts.source_index.has("c.JSONP(") {
        "c.JSONP("
    } else {
        return;
    };
    if facts.source_index.has("json.NewEncoder(") || facts.source_index.has("c.Stream(") {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_86,
        file,
        line,
        col,
        "Echo c.JSON allocates an encoder per response; pool the encoder or stream with json.NewEncoder",
        out,
    );
}

pub(crate) fn detect_perf_87(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has("echo.Context") {
        return;
    }
    let needle = if facts.source_index.has("c.BindWith(") {
        "c.BindWith("
    } else if facts.source_index.has("c.Bind(") {
        "c.Bind("
    } else {
        return;
    };
    if has_any(
        &facts.source_index,
        &["echo.Binder", "NewBinder()", "DefaultBinder{}"],
    ) {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_87,
        file,
        line,
        col,
        "Echo default binder runs full validation per request; use a custom binder for trusted paths",
        out,
    );
}

pub(crate) fn detect_perf_88(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["e.Static(", "e.File(", "echo.Static(", "Static("];
    let Some(&needle) = triggers
        .iter()
        .find(|n| facts.source_index.has(n))
    else {
        return;
    };
    if has_any(
        &facts.source_index,
        &["Cache-Control", "cacheControl", "SetCache", "MaxAge"],
    ) {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_88,
        file,
        line,
        col,
        "Static handler is missing cache headers; set explicit Cache-Control for static assets",
        out,
    );
}

pub(crate) fn detect_perf_89(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has("echo.HandlerFunc") {
        return;
    }
    let triggers = ["make([]", "make(map[", "json.Unmarshal(", "&MyConfig{}"];
    let Some(&needle) = triggers
        .iter()
        .find(|n| facts.source_index.has(n))
    else {
        return;
    };
    if facts.source_index.has("sync.Once") || facts.source_index.has("var once ") {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_89,
        file,
        line,
        col,
        "Echo middleware allocates per request; move construction to package scope or sync.Once",
        out,
    );
}

pub(crate) fn detect_perf_90(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has("echo.HandlerFunc") {
        return;
    }
    if !facts.source_index.has("c.Set(") {
        return;
    }
    if has_any(
        &facts.source_index,
        &[
            "c.Set(\"user_id\",",
            "c.Set(\"request_id\",",
            "c.Set(\"trace_id\",",
        ],
    ) {
        return;
    }
    let start = source.find("c.Set(").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_90,
        file,
        line,
        col,
        "c.Set in Echo middleware stores a value; prefer small scalars (ids, request ids) over large blobs",
        out,
    );
}