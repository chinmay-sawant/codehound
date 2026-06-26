use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_276(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0666"
            && (call.arguments[0].contains("sessions")
                || source.contains("session_data")
                || source.contains("X-Session-Data"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_276,
        file,
        line,
        col,
        "a session artifact is written with a world-readable and world-writable default mode",
        out,
    );
}

pub(crate) fn detect_cwe_277(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let clears_umask = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Umask"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    });
    if !clears_umask {
        return;
    }

    let Some(mkdir_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.MkdirAll"
            && call.arguments.len() >= 2
            && call.arguments[1].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(mkdir_call.start_byte);
    emit::push_finding(
        &META_CWE_277,
        file,
        line,
        col,
        "umask is cleared before creating a world-writable directory",
        out,
    );
}

pub(crate) fn detect_cwe_278(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(open_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.OpenFile"
            && call.arguments.len() >= 3
            && call.arguments[2].contains("os.FileMode(hdr.Mode)")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_278,
        file,
        line,
        col,
        "archive entry permissions are reapplied directly from untrusted metadata during extraction",
        out,
    );
}

pub(crate) fn detect_cwe_279(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("strconv.ParseUint(") {
        return;
    }

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_279,
        file,
        line,
        col,
        "the handler parses a requested mode but still writes the file with a hard-coded world-writable mode",
        out,
    );
}

pub(crate) fn detect_cwe_281(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Mode()") {
        return;
    }

    let Some(create_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Create")
    else {
        return;
    };

    if !source.contains("io.Copy(out, in)") {
        return;
    }

    let (line, col) = unit.line_col(create_call.start_byte);
    emit::push_finding(
        &META_CWE_281,
        file,
        line,
        col,
        "backup recreation uses os.Create and loses the source file's original permission bits",
        out,
    );
}

pub(crate) fn detect_cwe_921(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let world_readable_secret = source.contains("/tmp/integration.key")
        && source.contains("WriteFile(")
        && source.contains("0644");
    if !world_readable_secret {
        return;
    }
    if source.contains("APP_SECRET_DIR") || source.contains("0600") {
        return;
    }

    let start_byte = source.find("/tmp/integration.key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_921,
        file,
        line,
        col,
        "sensitive integration key material is stored in a world-readable temporary file",
        out,
    );
}
