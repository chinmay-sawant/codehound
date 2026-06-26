//! BP-6, BP-7, BP-8, BP-9 — concurrency/synchronisation bad practices.

use crate::core::ParsedUnit;
use crate::rules::Finding;
use super::helpers::{line_start_byte, push_at};

/// BP-6: sync.WaitGroup.Add inside the goroutine it tracks.
pub(crate) fn detect_bp_6_waitgroup_add_inside_goroutine(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !source.contains("go func") || !source.contains(".Add(") {
        return;
    }
    let mut in_goroutine = false;
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("go func") || trimmed.contains("go func(") {
            in_goroutine = true;
        }
        if in_goroutine && trimmed.contains(".Add(") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_6_META,
                line_start_byte(source, idx) + line.find(".Add(").unwrap_or(0),
                "WaitGroup.Add is inside the goroutine; call Add before launching it",
            );
        }
        if in_goroutine && (trimmed == "}" || trimmed == "}()" || trimmed == "}()") {
            in_goroutine = false;
        }
    }
}

/// BP-7: sync.Mutex copied by function parameter value.
pub(crate) fn detect_bp_7_mutex_passed_by_value(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("func ")
            && trimmed.contains(" sync.Mutex")
            && !trimmed.contains("*sync.Mutex")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_7_META,
                line_start_byte(source, idx) + line.find("sync.Mutex").unwrap_or(0),
                "sync.Mutex is passed by value; pass *sync.Mutex to avoid copying lock state",
            );
        }
    }
}

/// BP-8: deferred unlock on a mutex value copy.
pub(crate) fn detect_bp_8_defer_unlock_on_mutex_copy(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !(source.contains(" sync.Mutex")
        && source.contains("defer ")
        && source.contains(".Unlock()"))
    {
        return;
    }
    for (idx, line) in source.lines().enumerate() {
        if line.trim().starts_with("defer ") && line.contains(".Unlock()") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_8_META,
                line_start_byte(source, idx) + line.find(".Unlock()").unwrap_or(0),
                "defer unlock is operating on a mutex value copy",
            );
        }
    }
}

/// BP-9: select without default, timeout, or context cancellation.
pub(crate) fn detect_bp_9_select_without_escape(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let Some(pos) = source.find("select {") else {
        return;
    };
    let block = &source[pos..source[pos..]
        .find('}')
        .map(|end| pos + end)
        .unwrap_or(source.len())];
    let has_escape = block.contains("default:")
        || block.contains("time.After(")
        || block.contains("time.NewTimer(")
        || block.contains("ctx.Done()")
        || block.contains("context.Done()")
        || block.contains("<-stop")
        || block.contains("<-done");
    if !has_escape {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_9_META,
            pos,
            "select can block indefinitely without default, timeout, or context cancellation",
        );
    }
}
