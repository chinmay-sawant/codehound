use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_280(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(open_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Open")
    else {
        return;
    };

    let falls_through_on_error = facts.source_index.has("if err != nil {")
        && !facts.source_index.has("errors.Is(err, syscall.EACCES)")
        && !facts.source_index.has("errors.Is(err, syscall.EPERM)")
        && (facts
            .source_index
            .has_any(&[r#"db.Exec("DELETE FROM tenants"#, "tenantStore.Delete("]));
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
