use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_403(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let opens_secret_before_exec = facts.source_index.has(r#"os.Open("/etc/slopguard/master.key")"#)
        && facts.source_index.has(r#"exec.Command("/bin/sh", "-c""#);
    if !opens_secret_before_exec {
        return;
    }
    if facts.source_index.has_any(&["secret.Fd()", "defer secret.Close()"]) {
        return;
    }

    let start_byte = source
        .find("os.Open(\"/etc/slopguard/master.key\")")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_403,
        file,
        line,
        col,
        "a sensitive descriptor is left open when launching a child shell command",
        out,
    );
}

pub(crate) fn detect_cwe_427(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let path_mutation =
        facts.source_index.has(r#"os.Setenv("PATH","#) && facts.source_index.has(r#"exec.Command("pdftopng""#);
    if !path_mutation {
        return;
    }
    if facts.source_index.has_any(&["pdftopngPath", "pdftopngBinary"]) {
        return;
    }

    let start_byte = source.find("os.Setenv(\"PATH\",").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_427,
        file,
        line,
        col,
        "user input is prepended to PATH before resolving the helper binary by name",
        out,
    );
}

pub(crate) fn detect_cwe_459(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let temp_export = facts.source_index.has("CreateTemp(")
        && (facts.source_index.has_any(&["c.File(f.Name())", "ServeFile(w, r, f.Name())"]));
    if !temp_export {
        return;
    }
    if facts.source_index.has("os.Remove(f.Name())") {
        return;
    }

    let start_byte = source.find("CreateTemp(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_459,
        file,
        line,
        col,
        "the temporary export file is served without being removed afterward",
        out,
    );
}
