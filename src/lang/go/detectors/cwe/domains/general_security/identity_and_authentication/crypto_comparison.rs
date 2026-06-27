use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_204(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_missing_account_branch =
        facts.source_index.has("no account") && facts.source_index.has("StatusNotFound");
    let has_wrong_secret_branch =
        facts
            .source_index
            .has_any(&["bad password", "bad secret", "StatusUnauthorized"]);
    let has_uniform_failure = facts.source_index.has("invalid credentials");

    if !(has_missing_account_branch && has_wrong_secret_branch) || has_uniform_failure {
        return;
    }

    let start_byte = source.find("no account").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_204,
        file,
        line,
        col,
        "authentication failures return distinguishable responses for missing accounts and wrong credentials",
        out,
    );
}

pub(crate) fn detect_cwe_208(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if facts.source_index.has("subtle.ConstantTimeCompare(") {
        return;
    }
    if !(facts.source_index.has("for i := range expected")
        && facts.source_index.has("provided[i] != expected[i]"))
    {
        return;
    }

    let start_byte = source.find("for i := range expected").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_208,
        file,
        line,
        col,
        "secret comparison returns early on mismatched bytes instead of using a constant-time primitive",
        out,
    );
}

pub(crate) fn detect_cwe_385(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let early_exit_secret_compare = facts.source_index.has("for i := 0; i < len(provided); i++")
        && facts.source_index.has("if provided[i] != expected[i] {")
        && facts.source_index.has("return false");
    if !early_exit_secret_compare {
        return;
    }
    if facts.source_index.has("ConstantTimeCompare(") {
        return;
    }

    let start_byte = source
        .find("for i := 0; i < len(provided); i++")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_385,
        file,
        line,
        col,
        "the secret comparison exits on the first mismatch and leaks timing information",
        out,
    );
}
