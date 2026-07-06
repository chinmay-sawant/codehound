use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_648(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let privileged_chown = facts.source_index.has("os.Chown(")
        && facts.source_index.has("uid")
        && (facts
            .source_index
            .has_any(&[r#"PostForm("uid")"#, r#"FormValue("uid")"#]))
        && (facts
            .source_index
            .has_any(&[r#"PostForm("path")"#, r#"FormValue("path")"#]));
    if !privileged_chown {
        return;
    }
    if facts
        .source_index
        .has_any(&["uploadRoot", "spoolDir", "serviceUID", "Setuid("])
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

pub(crate) fn detect_cwe_708(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_chosen_owner = facts.source_index.has("owner_uid")
        && facts.source_index.has("os.Chown(")
        && (facts
            .source_index
            .has_any(&[r#"PostForm("dest")"#, r#"FormValue("dest")"#]));
    if !caller_chosen_owner {
        return;
    }
    if facts
        .source_index
        .has_any(&["spoolDir", "serviceUID", "serviceGID"])
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
