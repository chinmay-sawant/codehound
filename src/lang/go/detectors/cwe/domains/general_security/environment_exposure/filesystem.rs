use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_403(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let opens_secret_before_exec = source.contains("os.Open(\"/etc/slopguard/master.key\")")
        && source.contains("exec.Command(\"/bin/sh\", \"-c\"");
    if !opens_secret_before_exec {
        return;
    }
    if source.contains("secret.Fd()") || source.contains("defer secret.Close()") {
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

pub(crate) fn detect_cwe_427(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let path_mutation =
        source.contains("os.Setenv(\"PATH\",") && source.contains("exec.Command(\"pdftopng\"");
    if !path_mutation {
        return;
    }
    if source.contains("pdftopngPath") || source.contains("pdftopngBinary") {
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

pub(crate) fn detect_cwe_459(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let temp_export = source.contains("CreateTemp(")
        && (source.contains("c.File(f.Name())") || source.contains("ServeFile(w, r, f.Name())"));
    if !temp_export {
        return;
    }
    if source.contains("os.Remove(f.Name())") {
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
