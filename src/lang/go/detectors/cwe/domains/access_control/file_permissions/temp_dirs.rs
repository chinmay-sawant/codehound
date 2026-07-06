use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_378(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_file =
        facts.source_index.has("os.TempDir()") && facts.source_index.has("0666");
    if !insecure_temp_file {
        return;
    }
    if facts
        .source_index
        .has_any(&["CreateTemp(", "Chmod(f.Name(), 0600)"])
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.TempDir()") {
        idx
    } else {
        source.find("0666").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_378,
        file,
        line,
        col,
        "a temp file is created with world-accessible permissions in the shared temp area",
        out,
    );
}

pub(crate) fn detect_cwe_379(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_dir = facts.source_index.has("MkdirAll(dir, 0777)")
        && (facts
            .source_index
            .has_any(&["/tmp/shared-reports", "/tmp/shared-sessions"]));
    if !insecure_temp_dir {
        return;
    }
    if facts
        .source_index
        .has_any(&["MkdirTemp(", "Chmod(dir, 0700)"])
    {
        return;
    }

    let start_byte = source.find("MkdirAll(dir, 0777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_379,
        file,
        line,
        col,
        "a temporary file is staged inside a shared world-writable directory",
        out,
    );
}
