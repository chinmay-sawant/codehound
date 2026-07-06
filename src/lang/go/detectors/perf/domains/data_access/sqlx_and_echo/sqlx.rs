use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_81(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["db.Select(", "db.Queryx(", "db.QueryxContext("];
    let Some(&needle) = triggers.iter().find(|n| facts.source_index.has(n)) else {
        return;
    };
    if !facts.source_index.has("IN (?)") {
        return;
    }
    if facts.source_index.has("chunk")
        || facts.source_index.has("Chunked")
        || facts.source_index.has("batchIDs")
    {
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

pub(crate) fn detect_perf_84(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index) {
        return;
    }
    let triggers = [
        "db.Beginx(",
        "db.MustBegin(",
        "tx, err := db.Beginx",
        "tx := db.MustBegin",
    ];
    let Some(&needle) = triggers.iter().find(|n| facts.source_index.has(n)) else {
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
