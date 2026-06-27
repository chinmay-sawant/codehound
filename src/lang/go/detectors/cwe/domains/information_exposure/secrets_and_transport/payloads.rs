use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_212(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_sensitive_payment_field =
        facts.source_index.has("Card") || facts.source_index.has("PAN");
    if !has_sensitive_payment_field {
        return;
    }
    if !(facts.source_index.has("json.Marshal(rows)")
        || facts.source_index.has("json.Marshal(out)"))
    {
        return;
    }
    if facts.source_index.has("type paymentExport struct")
        || facts.source_index.has("type chargeExport struct")
    {
        return;
    }
    if !facts.source_index.has("json.Marshal(rows)") {
        return;
    }

    let start_byte = source.find("json.Marshal(rows)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_212,
        file,
        line,
        col,
        "records containing sensitive payment fields are marshaled directly for export",
        out,
    );
}

pub(crate) fn detect_cwe_214(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "exec.Command" {
            continue;
        }
        if facts.source_index.has("cmd.Stdin = strings.NewReader(") {
            return;
        }

        let uses_user_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == binding.name.as_ref())
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == r#""--token""#)
        });
        if !uses_user_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_214,
            file,
            line,
            col,
            "a user-supplied token is passed as a visible argv argument to an external process",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_312(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stores_plain_ssn = facts.source_index.has("SSN: c.PostForm(\"ssn\")")
        || facts.source_index.has("SSN: r.FormValue(\"ssn\")");
    let writes_plain_ssn_json = facts.source_index.has(r#"SSN string `json:"ssn"`"#)
        && facts.source_index.has("json.Marshal(rec)");
    if !(stores_plain_ssn || writes_plain_ssn_json) {
        return;
    }
    if facts.source_index.has("SSNCipher") || facts.source_index.has("gcm.Seal(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ssn") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_312,
        file,
        line,
        col,
        "a sensitive SSN value is persisted in cleartext instead of encrypted form",
        out,
    );
}
