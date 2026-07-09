use super::super::super::super::common::{is_hot_path, is_request_path};
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-51: `unsafe.Pointer` in a request handler without benchmark justification.
pub(crate) fn detect_perf_52(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.GC" {
            continue;
        }
        emit_at(
            unit,
            &META_PERF_52,
            call.start_byte,
            "runtime.GC() forces a stop-the-world GC; remove unless required for tests or controlled shutdown",
            out,
        );
        return;
    }
}

/// PERF-53: package-level `math/rand` on the request path.
pub(crate) fn detect_perf_53(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index) {
        return;
    }
    let trig = ["rand.Intn(", "rand.Float64(", "rand.Read("];
    if !facts.source_index.has_any(&trig)
        || facts.source_index.has("rand.NewSource(")
        || facts.source_index.has("rand.New(")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_53,
        first_pos(source, &trig),
        "package-level math/rand on a request path contends on a global mutex; use a per-goroutine rand.Source",
        out,
    );
}

/// PERF-54: `strings.Builder{}` allocated on a hot path without Reset/pool.
pub(crate) fn detect_perf_54(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let Some(byte) = source.find("strings.Builder{}") else {
        return;
    };
    if facts.source_index.has("Reset()")
        || facts.source_index.has("var builderPool =")
        || facts.source_index.has("sync.Pool")
        || source.contains(".Reset()")
    {
        return;
    }
    let in_loop = facts
        .for_ranges
        .iter()
        .any(|(s, e)| byte >= *s && byte < *e);
    if !is_hot_path(source, byte, &facts.source_index, in_loop) {
        return;
    }
    emit_at(
        unit,
        &META_PERF_54,
        byte,
        "strings.Builder is allocated on a hot path; pool or hoist the builder and call Reset",
        out,
    );
}

/// PERF-55: `bufio.NewScanner` with no explicit `Buffer` sizing.
pub(crate) fn detect_perf_55(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if facts.source_index.has("bufio.NewScanner(") && !facts.source_index.has(".Buffer(") {
        emit_at(
            unit,
            &META_PERF_55,
            source.find("bufio.NewScanner(").unwrap_or(0),
            "bufio.NewScanner is used without an explicit Buffer sizing; large inputs will silently fail at 64KiB",
            out,
        );
    }
}
