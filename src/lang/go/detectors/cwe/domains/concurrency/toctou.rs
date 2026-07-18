use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_367(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: both Stat and ReadFile tokens must appear.
    // Primary evidence is call_facts (shared path expression), not exact `(target)` text.
    if !facts.source_index.has("os.Stat(") || !facts.source_index.has("os.ReadFile") {
        return;
    }

    // Primary signal: call facts — `os.Stat` and `os.ReadFile` on the same path argument.
    // Shared first-arg text is the co-use proof (TOCTOU window); argument names need not be
    // the fixture identifier `target`.
    let stat_calls: Vec<_> = facts
        .call_facts
        .iter()
        .filter(|call| call.callee.as_ref() == "os.Stat" && !call.arguments.is_empty())
        .collect();
    if stat_calls.is_empty() {
        return;
    }

    let Some(stat_call) = stat_calls.iter().find(|stat| {
        let path = stat.arguments[0].as_ref();
        facts.call_facts.iter().any(|call| {
            call.callee.as_ref() == "os.ReadFile"
                && call
                    .arguments
                    .first()
                    .is_some_and(|arg| arg.as_ref() == path)
        })
    }) else {
        return;
    };

    let (line, col) = unit.line_col(stat_call.start_byte);
    emit::push_finding(
        &META_CWE_367,
        file,
        line,
        col,
        "the code checks a file path with Stat before later using it, creating a TOCTOU race window",
        out,
    );
}
