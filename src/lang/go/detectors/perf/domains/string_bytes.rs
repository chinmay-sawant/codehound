//! Migrated from hot_path_misc.rs: domain-specific String/Bytes PERF detectors.
//!
//! PERF-159, PERF-178, PERF-179, PERF-186, PERF-203

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{is_handler_shaped, is_in_loop};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_159(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("json.NewDecoder") {
        return;
    }
    if !source.contains(".Decode(") {
        return;
    }
    for call in &facts.calls {
        if call.callee.as_ref() != "json.NewDecoder" {
            continue;
        }
        let first = call.arguments.first().map(|a| a.as_ref()).unwrap_or("");
        let prebuffered = first.contains("bytes.NewReader")
            || first.contains("bytes.NewBuffer")
            || first.contains("strings.NewReader")
            || (first.contains("[]byte") && first.contains(","));
        if !prebuffered {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_159,
            file,
            line,
            col,
            "json.NewDecoder on pre-buffered data; use json.Unmarshal for []byte to avoid the reader allocation",
            out,
        );
    }
}

pub(crate) fn detect_perf_178(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut formats: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| {
            c.callee.as_ref().ends_with(".Format") && !c.callee.as_ref().ends_with("AppendFormat")
        })
        .collect();
    if formats.len() < 2 {
        return;
    }
    formats.sort_by_key(|c| c.start_byte);
    for pair in formats.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.callee.as_ref() != b.callee.as_ref() {
            continue;
        }
        if b.start_byte - a.start_byte > 1024 {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_178,
            file,
            line,
            col,
            "time.Format called repeatedly with the same format string; use time.AppendFormat to write into a pooled buffer",
            out,
        );
        return;
    }
}

pub(crate) fn detect_perf_179(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("strings.Replace(") {
        return;
    }

    let mut keys: Vec<(String, usize)> = Vec::new();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Replace" {
            continue;
        }
        if call.arguments.len() < 3 {
            continue;
        }
        let key = format!(
            "{}\u{1}{}",
            call.arguments[1].as_ref(),
            call.arguments[2].as_ref()
        );
        keys.push((key, call.start_byte));
    }
    keys.sort_by_key(|(_, b)| *b);
    for pair in keys.windows(2) {
        if pair[0].0 != pair[1].0 {
            continue;
        }
        if pair[1].1 - pair[0].1 > 2048 {
            continue;
        }
        let (line, col) = unit.line_col(pair[0].1);
        emit::push_finding(
            &META_PERF_179,
            file,
            line,
            col,
            "strings.Replace with the same old/new pair called repeatedly; build a strings.Replacer once and reuse it",
            out,
        );
        return;
    }
}

pub(crate) fn detect_perf_186(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Fields" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_186,
            file,
            line,
            col,
            "strings.Fields in a hot path; use strings.IndexByte to walk whitespace and slice once per token",
            out,
        );
    }
}

pub(crate) fn detect_perf_203(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut strings: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref().ends_with(".String"))
        .collect();
    if strings.len() < 2 {
        return;
    }
    strings.sort_by_key(|c| c.start_byte);
    for pair in strings.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.callee.as_ref() != b.callee.as_ref() {
            continue;
        }
        if b.start_byte - a.start_byte > 1024 {
            continue;
        }
        // The receiver must look like an IP address variable.
        let callee = a.callee.as_ref();
        if callee.to_lowercase().contains("ip.") || callee.starts_with("ip.") {
            let (line, col) = unit.line_col(a.start_byte);
            emit::push_finding(
                &META_PERF_203,
                file,
                line,
                col,
                "ip.String() called repeatedly on the same IP; cache the result or write directly to a buffer",
                out,
            );
            return;
        }
    }
}
