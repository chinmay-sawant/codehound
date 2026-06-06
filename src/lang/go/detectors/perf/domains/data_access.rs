//! PERF-071 through PERF-090: GORM, sqlx, and Echo data-access patterns.

use super::super::common::is_request_path;
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
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
