use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_86(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("echo.Context") {
        return;
    }
    let needle = if source.contains("c.JSON(") {
        "c.JSON("
    } else if source.contains("c.JSONP(") {
        "c.JSONP("
    } else {
        return;
    };
    if source.contains("json.NewEncoder(") || source.contains("c.Stream(") {
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

pub(crate) fn detect_perf_87(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("echo.Context") {
        return;
    }
    let needle = if source.contains("c.BindWith(") {
        "c.BindWith("
    } else if source.contains("c.Bind(") {
        "c.Bind("
    } else {
        return;
    };
    if has_any(source, &["echo.Binder", "NewBinder()", "DefaultBinder{}"]) {
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

pub(crate) fn detect_perf_88(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["e.Static(", "e.File(", "echo.Static(", "Static("];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    if has_any(
        source,
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

pub(crate) fn detect_perf_89(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("echo.HandlerFunc") {
        return;
    }
    let triggers = ["make([]", "make(map[", "json.Unmarshal(", "&MyConfig{}"];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    if source.contains("sync.Once") || source.contains("var once ") {
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

pub(crate) fn detect_perf_90(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("echo.HandlerFunc") {
        return;
    }
    if !source.contains("c.Set(") {
        return;
    }
    if has_any(
        source,
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
