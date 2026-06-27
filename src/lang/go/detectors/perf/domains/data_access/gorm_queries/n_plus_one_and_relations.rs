use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_71(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    if facts.source_index.has("Preload(") || facts.source_index.has(".Joins(") {
        return;
    }
    let triggers = ["db.Find", "db.First", "db.Take", "db.Where"];
    let Some(start) = call_in_loop_with(facts, &triggers) else {
        return;
    };
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_71,
        file,
        line,
        col,
        "GORM query inside a loop body suggests an N+1 access pattern; use Preload or batch the fetch",
        out,
    );
}

pub(crate) fn detect_perf_73(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if facts.source_index.has("Preload(") || facts.source_index.has(".Joins(") {
        return;
    }
    if !has_any(
        &facts.source_index,
        &["db.Find(", "db.First(", "db.Take("],
    ) {
        return;
    }
    let relations = [
        ".Orders",
        ".Items",
        ".Author",
        ".Comments",
        ".Profile",
        ".Children",
        ".Posts",
        ".Tags",
        ".Addresses",
    ];
    if !has_any(&facts.source_index, &relations) {
        return;
    }
    let needle = ["db.Find(", "db.First(", "db.Take("]
        .iter()
        .find(|n| facts.source_index.has(n))
        .copied()
        .unwrap_or("db.Find(");
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_73,
        file,
        line,
        col,
        "GORM relation field accessed without Preload/Joins; the relation will not be loaded",
        out,
    );
}

pub(crate) fn detect_perf_74(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index) {
        return;
    }
    if facts.source_index.has(".Select(") {
        return;
    }
    let triggers = ["db.Find(", "db.First(", "db.Take(", "db.Where("];
    let Some(&needle) = triggers
        .iter()
        .find(|n| facts.source_index.has(n))
    else {
        return;
    };
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_74,
        file,
        line,
        col,
        "GORM query reads all columns; project only the fields the handler returns with Select",
        out,
    );
}

pub(crate) fn detect_perf_78(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["db.Raw(", "db.Exec("];
    let Some(&needle) = triggers
        .iter()
        .find(|n| facts.source_index.has(n))
    else {
        return;
    };
    let after_idx = source.find(needle).unwrap_or(0);
    let after = &source[after_idx..];
    if !substr_has_any(
        after,
        &["WHERE", "ORDER BY", "JOIN", "where ", "order by ", "join "],
    ) {
        return;
    }
    if facts.source_index.has("// index-backed")
        || facts.source_index.has("/* index */")
        || facts.source_index.has("USING INDEX")
        || facts.source_index.has("use index")
    {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_78,
        file,
        line,
        col,
        "Raw/Exec query with WHERE/JOIN/ORDER BY; confirm an index backs the clause",
        out,
    );
}