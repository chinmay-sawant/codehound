use super::super::super::super::common::is_request_path;
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
pub(crate) fn detect_perf_53(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let trig = ["rand.Intn(", "rand.Float64(", "rand.Read("];
    if !trig.iter().any(|t| source.contains(t))
        || source.contains("rand.NewSource(")
        || source.contains("rand.New(")
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

/// PERF-54: `strings.Builder{}` allocated in a request handler.
pub(crate) fn detect_perf_54(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("strings.Builder{}") {
        return;
    }
    if source.contains("Reset()")
        || source.contains("var builderPool =")
        || source.contains("sync.Pool{")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_54,
        source.find("strings.Builder{}").unwrap_or(0),
        "strings.Builder is allocated per request; pool or hoist the builder and call Reset",
        out,
    );
}

/// PERF-55: `bufio.NewScanner` with no explicit `Buffer` sizing.
pub(crate) fn detect_perf_55(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if source.contains("bufio.NewScanner(") && !source.contains(".Buffer(") {
        emit_at(
            unit,
            &META_PERF_55,
            source.find("bufio.NewScanner(").unwrap_or(0),
            "bufio.NewScanner is used without an explicit Buffer sizing; large inputs will silently fail at 64KiB",
            out,
        );
    }
}
