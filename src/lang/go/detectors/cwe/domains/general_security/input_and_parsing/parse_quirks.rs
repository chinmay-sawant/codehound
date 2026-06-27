use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_838(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let invalid_utf8 =
        facts.source_index.has("application/json; charset=utf-8") && facts.source_index.has("0xC3, 0x28");
    if !invalid_utf8 {
        return;
    }

    let start_byte = source.find("0xC3, 0x28").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_838,
        file,
        line,
        col,
        "invalid byte sequences are emitted while declaring UTF-8 JSON output",
        out,
    );
}

pub(crate) fn detect_cwe_1286(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loose_json_config = (facts.source_index.has_any(&["SaveHookConfig(", "SaveHookConfigPure("]))
        && (facts.source_index.has_any(&["json.Unmarshal(body, &cfg)", "json.NewDecoder(r.Body).Decode(&cfg)"]))
        && facts.source_index.has("hook_configs");
    if !loose_json_config {
        return;
    }
    if facts.source_index.has_any(&["DisallowUnknownFields()", "ParseRequestURI(cfg.URL)"]) {
        return;
    }

    let start_byte = source
        .find("json.Unmarshal(body, &cfg)")
        .or_else(|| source.find("json.NewDecoder(r.Body).Decode(&cfg)"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1286,
        file,
        line,
        col,
        "webhook configuration JSON is accepted without strict syntax and URL validation",
        out,
    );
}

pub(crate) fn detect_cwe_1389(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let implicit_radix = (facts.source_index.has_any(&["ReserveSeats(", "ReserveSeatsPure("]))
        && facts.source_index.has("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if facts.source_index.has("strconv.ParseInt(raw, 10, 64)") {
        return;
    }

    let start_byte = source.find("strconv.ParseInt(raw, 0, 64)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1389,
        file,
        line,
        col,
        "seat counts are parsed with base 0 and may accept alternate-radix prefixes unexpectedly",
        out,
    );
}
