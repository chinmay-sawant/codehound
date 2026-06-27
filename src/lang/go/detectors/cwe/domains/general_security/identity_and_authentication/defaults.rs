use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_841(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let workflow_skip = facts.source_index.has("ResetAccount")
        && facts.source_index.has("new_password")
        && facts.source_index.has("password");
    if !workflow_skip {
        return;
    }
    if (facts.source_index.has("MFAPassed") && facts.source_index.has("if !acct.MFAPassed"))
        || facts.source_index.has("if !accountMFAPassed[email]")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_841,
        file,
        line,
        col,
        "the reset workflow changes credentials without enforcing MFA completion",
        out,
    );
}

pub(crate) fn detect_cwe_842(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wrong_default_group =
        facts.source_index.has("RegisterMember") && facts.source_index.has(r#"Group: "administrators""#);
    if !wrong_default_group {
        return;
    }
    if facts.source_index.has(r#"Group: "members""#) {
        return;
    }

    let start_byte = source.find("Group: \"administrators\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_842,
        file,
        line,
        col,
        "newly registered users are assigned to an administrator group by default",
        out,
    );
}
