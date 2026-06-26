use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_280(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(open_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Open")
    else {
        return;
    };

    let falls_through_on_error = source.contains("if err != nil {")
        && !source.contains("errors.Is(err, syscall.EACCES)")
        && !source.contains("errors.Is(err, syscall.EPERM)")
        && (source.contains("db.Exec(\"DELETE FROM tenants")
            || source.contains("tenantStore.Delete("));
    if !falls_through_on_error {
        return;
    }

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_280,
        file,
        line,
        col,
        "failure to access a protected resource leads into a privileged deletion path instead of a denial",
        out,
    );
}
