use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_112(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_xml_unmarshal = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "xml.Unmarshal")
        || facts.source_index.has("xml.Unmarshal(");
    if !has_xml_unmarshal {
        return;
    }

    let has_untrusted_payload = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && crate::engine::scratch_contains(source, "xml.Unmarshal(", &binding.name, ",")
    });
    if !has_untrusted_payload {
        return;
    }

    let has_validation = facts.source_index.has_any(&[".MatchString(", " <= 0"]);
    if has_validation {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "xml.Unmarshal")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_112,
        file,
        line,
        col,
        "untrusted XML is unmarshaled without subsequent field-level validation",
        out,
    );
}

pub(crate) fn detect_cwe_611(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unsafe_xml = facts.source_index.has("xml.NewDecoder(")
        && facts.source_index.has("dec.Strict = false")
        && facts.source_index.has("Decode(&catalog)");
    if !unsafe_xml {
        return;
    }
    if facts
        .source_index
        .has_any(&["<!DOCTYPE", "dec.Strict = true", "LimitReader"])
    {
        return;
    }

    let start_byte = source.find("dec.Strict = false").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_611,
        file,
        line,
        col,
        "untrusted XML is parsed with strict mode disabled and no DOCTYPE rejection",
        out,
    );
}
