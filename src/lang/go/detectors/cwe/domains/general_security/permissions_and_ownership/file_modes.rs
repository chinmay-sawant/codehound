use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_250(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

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

    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" {
            continue;
        }
        if facts.source_index.has("if err := os.WriteFile(") {
            return;
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
    let source = unit.source.as_ref();

    let permissive_upload_mode = (facts
        .source_index
        .has_any(&[r#"FormFile("contract")"#, r#"FormFile("contract")"#]))
        && facts.source_index.has("/srv/contracts")
        && facts.source_index.has("os.Chmod(dest, 0o777)");
    if !permissive_upload_mode {
        return;
    }
    if facts.source_index.has("filepath.Base(") || facts.source_index.has("os.Chmod(dest, 0o600)") {
        return;
    }

    let start_byte = source.find("os.Chmod(dest, 0o777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_552,
        file,
        line,
        col,
        "uploaded contract files are made world-accessible after storage",
        out,
    );
}
