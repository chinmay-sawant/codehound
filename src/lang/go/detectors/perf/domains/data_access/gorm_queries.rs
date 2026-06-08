//! PERF-071 through PERF-090: GORM, sqlx, and Echo data-access patterns.

use super::super::super::common::is_request_path;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

fn call_in_loop_with(facts: &GoPerfFacts, needles: &[&str]) -> Option<usize> {
    facts.calls.iter().find_map(|c| {
        if c.enclosing_loop.is_some() && needles.iter().any(|n| c.callee.contains(n)) {
            Some(c.start_byte)
        } else {
            None
        }
    })
}

fn has_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| source.contains(n))
}
pub(crate) fn detect_perf_71(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if source.contains("Preload(") || source.contains(".Joins(") {
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

pub(crate) fn detect_perf_72(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let triggers = [
        "db.Transaction(",
        "db.Begin(",
        "tx := db.Begin(",
        "tx, err := db.Begin(",
    ];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_72,
        file,
        line,
        col,
        "GORM transaction opened inside a request handler; collapse to a single statement or hoist the work",
        out,
    );
}

pub(crate) fn detect_perf_73(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if source.contains("Preload(") || source.contains(".Joins(") {
        return;
    }
    if !has_any(source, &["db.Find(", "db.First(", "db.Take("]) {
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
    if !has_any(source, &relations) {
        return;
    }
    let needle = ["db.Find(", "db.First(", "db.Take("]
        .iter()
        .find(|n| source.contains(**n))
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

pub(crate) fn detect_perf_74(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    if source.contains(".Select(") {
        return;
    }
    let triggers = ["db.Find(", "db.First(", "db.Take(", "db.Where("];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
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

pub(crate) fn detect_perf_75(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    if !source.contains("db.Session(&gorm.Session{") {
        return;
    }
    if source.contains("var sessionOpts =")
        || source.contains("var defaultSession =")
        || source.contains("sessionOnce")
    {
        return;
    }
    let start = source.find("db.Session(&gorm.Session{").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_75,
        file,
        line,
        col,
        "GORM session is constructed per request; hoist Session options to package scope or sync.Once",
        out,
    );
}

pub(crate) fn detect_perf_76(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if source.contains("CreateInBatches") {
        return;
    }
    let Some(start) = call_in_loop_with(facts, &["db.Create"]) else {
        return;
    };
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_76,
        file,
        line,
        col,
        "db.Create is called inside a loop; batch with CreateInBatches or hoist the create out",
        out,
    );
}

pub(crate) fn detect_perf_77(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("db.Save(") {
        return;
    }
    if source.contains("db.Create(") {
        return;
    }
    if source.contains(".Updates(") {
        return;
    }
    let start = source.find("db.Save(").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_77,
        file,
        line,
        col,
        "db.Save in an update-only path; use db.Updates with the changed fields to avoid full-row writes",
        out,
    );
}

pub(crate) fn detect_perf_78(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["db.Raw(", "db.Exec("];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    let after_idx = source.find(needle).unwrap_or(0);
    let after = &source[after_idx..];
    if !has_any(
        after,
        &["WHERE", "ORDER BY", "JOIN", "where ", "order by ", "join "],
    ) {
        return;
    }
    if source.contains("// index-backed")
        || source.contains("/* index */")
        || source.contains("USING INDEX")
        || source.contains("use index")
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

pub(crate) fn detect_perf_79(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = [
        "sql.Open(",
        "gorm.Open(",
        "gorm.New(",
        "postgres.Open(",
        "mysql.Open(",
    ];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    if has_any(
        source,
        &[
            "SetMaxOpenConns(",
            "SetMaxIdleConns(",
            "SetConnMaxLifetime(",
        ],
    ) {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_79,
        file,
        line,
        col,
        "database handle opened without SetMaxOpenConns / SetMaxIdleConns / SetConnMaxLifetime",
        out,
    );
}

pub(crate) fn detect_perf_80(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let triggers = ["Pluck(", "Distinct("];
    let Some(&needle) = triggers.iter().find(|n| source.contains(*n)) else {
        return;
    };
    if source.contains(".Limit(") {
        return;
    }
    let start = source.find(needle).unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_80,
        file,
        line,
        col,
        "Pluck/Distinct query has no Limit; bound the result set with Limit, batching, or streaming",
        out,
    );
}
