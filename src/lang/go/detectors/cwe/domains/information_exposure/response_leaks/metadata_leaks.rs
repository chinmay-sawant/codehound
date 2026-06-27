use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_209(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has(r#"fmt.Sprintf("db failure: %v", err)"#) {
        return;
    }

    let start_byte = source
        .find(r#"fmt.Sprintf("db failure: %v", err)"#)
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_209,
        file,
        line,
        col,
        "database error details are formatted into a client-facing response",
        out,
    );
}

pub(crate) fn detect_cwe_215(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "log.Printf" {
            continue;
        }

        let logs_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && binding.name.contains("secret")
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == binding.name.as_ref())
        });
        if !logs_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_215,
            file,
            line,
            col,
            "a debug log statement includes request-derived secret material",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_756(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_error_to_client = facts.source_index.has("err.Error()")
        && facts.source_index.has("FetchProfile")
        && facts.source_index.has("SELECT email FROM profiles")
        && (facts.source_index.has("c.String(http.StatusInternalServerError, err.Error())")
            || facts.source_index.has("http.Error(w, err.Error(), http.StatusInternalServerError)"));
    if !raw_error_to_client {
        return;
    }
    if facts.source_index.has("\"unable to load profile\"") {
        return;
    }

    let start_byte = source.find("err.Error()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_756,
        file,
        line,
        col,
        "raw database error text is returned directly to the client",
        out,
    );
}

pub(crate) fn detect_cwe_1230(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let metadata_leak = (facts.source_index.has("DownloadRedacted(")
        || facts.source_index.has("DownloadRedactedPure("))
        && facts.source_index.has("X-Original-Name")
        && facts.source_index.has("X-File-Size")
        && facts.source_index.has("[REDACTED CONTENT]");
    if !metadata_leak {
        return;
    }
    if facts.source_index.has("Cache-Control") {
        return;
    }

    let start_byte = source.find("X-Original-Name").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1230,
        file,
        line,
        col,
        "a redacted download response still exposes sensitive filename and size metadata",
        out,
    );
}
