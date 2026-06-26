use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
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
