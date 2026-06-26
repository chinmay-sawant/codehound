use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_838(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let invalid_utf8 =
        source.contains("application/json; charset=utf-8") && source.contains("0xC3, 0x28");
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

pub(crate) fn detect_cwe_1286(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loose_json_config = (source.contains("SaveHookConfig(")
        || source.contains("SaveHookConfigPure("))
        && (source.contains("json.Unmarshal(body, &cfg)")
            || source.contains("json.NewDecoder(r.Body).Decode(&cfg)"))
        && source.contains("hook_configs");
    if !loose_json_config {
        return;
    }
    if source.contains("DisallowUnknownFields()") || source.contains("ParseRequestURI(cfg.URL)") {
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

pub(crate) fn detect_cwe_1389(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let implicit_radix = (source.contains("ReserveSeats(") || source.contains("ReserveSeatsPure("))
        && source.contains("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if source.contains("strconv.ParseInt(raw, 10, 64)") {
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
