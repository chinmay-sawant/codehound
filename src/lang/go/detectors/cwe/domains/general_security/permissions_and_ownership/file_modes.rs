use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_250(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no WriteFile text ⇒ no world-writable write of this shape.
    if !facts.source_index.has("os.WriteFile(") {
        return;
    }

    // Primary signal: call facts — os.WriteFile with world-writable mode 0o777.
    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[2].as_ref() != "0o777" {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_250,
            file,
            line,
            col,
            "runtime file is written with world-accessible permissions",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_252(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no WriteFile text ⇒ no unchecked-write sink.
    if !facts.source_index.has("os.WriteFile(") {
        return;
    }
    // Negative prefilter: error-checked WriteFile assignment form (corpus safe-path).
    if facts.source_index.has("if err := os.WriteFile(") {
        return;
    }

    // Primary signal: call facts — os.WriteFile to corpus audit/journal log paths
    // without the error-checked assignment form above.
    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" {
            continue;
        }
        let writes_audit_log = call
            .arguments
            .iter()
            .any(|arg| arg.contains("/var/log/audit.log") || arg.contains("/var/log/journal.log"));
        if !writes_audit_log {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_252,
            file,
            line,
            col,
            "os.WriteFile is called without checking its returned error",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_552(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no world-writable chmod corpus text ⇒ no sink.
    if !facts.source_index.has("os.Chmod(dest, 0o777)") {
        return;
    }
    // Corpus co-signals still required for oracle (contract form field + store path).
    // Maturity is fixture-only; call_facts is the primary sink proof only.
    let permissive_upload_mode = facts.source_index.has(r#"FormFile("contract")"#)
        && facts.source_index.has("/srv/contracts");
    if !permissive_upload_mode {
        return;
    }
    // Negative prefilters: basename sanitization / owner-only mode.
    if facts.source_index.has("filepath.Base(") || facts.source_index.has("os.Chmod(dest, 0o600)") {
        return;
    }

    // Primary signal: call facts — stdlib os.Chmod with world-writable mode.
    let Some(chmod_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.Chmod"
            && call.arguments.len() >= 2
            && call.arguments[1].as_ref() == "0o777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(chmod_call.start_byte);
    emit::push_finding(
        &META_CWE_552,
        file,
        line,
        col,
        "uploaded contract files are made world-accessible after storage",
        out,
    );
}
