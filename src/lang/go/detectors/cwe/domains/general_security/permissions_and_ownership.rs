use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
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
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" {
            continue;
        }
        if source.contains("if err := os.WriteFile(") {
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

    let permissive_upload_mode = (source.contains("FormFile(\"contract\")")
        || source.contains("FormFile(\"contract\")"))
        && source.contains("/srv/contracts")
        && source.contains("os.Chmod(dest, 0o777)");
    if !permissive_upload_mode {
        return;
    }
    if facts.source_index.has("filepath.Base(") || source.contains("os.Chmod(dest, 0o600)") {
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


pub(crate) fn detect_cwe_648(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let privileged_chown = source.contains("os.Chown(")
        && source.contains("uid")
        && (source.contains("PostForm(\"uid\")") || source.contains("FormValue(\"uid\")"))
        && (source.contains("PostForm(\"path\")") || source.contains("FormValue(\"path\")"));
    if !privileged_chown {
        return;
    }
    if source.contains("uploadRoot")
        || source.contains("spoolDir")
        || source.contains("serviceUID")
        || source.contains("Setuid(")
    {
        return;
    }

    let start_byte = source.find("os.Chown(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_648,
        file,
        line,
        col,
        "the handler passes caller-controlled values into a privileged ownership-change API",
        out,
    );
}


pub(crate) fn detect_cwe_708(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_chosen_owner = source.contains("owner_uid")
        && source.contains("os.Chown(")
        && (source.contains("PostForm(\"dest\")") || source.contains("FormValue(\"dest\")"));
    if !caller_chosen_owner {
        return;
    }
    if source.contains("spoolDir") || source.contains("serviceUID") || source.contains("serviceGID")
    {
        return;
    }

    let start_byte = source.find("owner_uid").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_708,
        file,
        line,
        col,
        "the caller chooses both the ownership target and uid for a file operation",
        out,
    );
}


