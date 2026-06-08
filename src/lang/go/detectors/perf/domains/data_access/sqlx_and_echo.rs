//! PERF-071 through PERF-090: GORM, sqlx, and Echo data-access patterns.

use super::super::super::common::is_request_path;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_perf_81(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["db.Select(", "db.Queryx(", "db.QueryxContext("];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    if !source.contains("IN (?)") {
        return;
    }
    if source.contains("chunk") || source.contains("Chunked") || source.contains("batchIDs") {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_81,
        file,
        line,
        col,
        "sqlx IN (?) expands an unbounded slice into one query; chunk the input first",
        out,
    );
}

pub(crate) fn detect_perf_82(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let Some(start) = call_in_loop_with(facts, &["rows.StructScan"]) else {
        return;
    };
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_82,
        file,
        line,
        col,
        "rows.StructScan inside a for rows.Next() loop; pre-allocate the destination slice",
        out,
    );
}

pub(crate) fn detect_perf_83(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let Some(start) = call_in_loop_with(facts, &["rows.MapScan"]) else {
        return;
    };
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_83,
        file,
        line,
        col,
        "rows.MapScan inside a for rows.Next() loop on a hot path; switch to StructScan with a typed destination",
        out,
    );
}

pub(crate) fn detect_perf_84(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let triggers = [
        "db.Beginx(",
        "db.MustBegin(",
        "tx, err := db.Beginx",
        "tx := db.MustBegin",
    ];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_84,
        file,
        line,
        col,
        "sqlx transaction opened inside handler; collapse to a single statement or shorter transaction",
        out,
    );
}

pub(crate) fn detect_perf_85(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let Some(start) = call_in_loop_with(facts, &["sqlx.Named", "sqlx.In"]) else {
        return;
    };
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_85,
        file,
        line,
        col,
        "sqlx.Named / sqlx.In inside a loop with a stable query shape; precompile the query once",
        out,
    );
}

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
