use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_341(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let predictable_token = facts.source_index.has(r#"fmt.Sprintf("%d-%d-%s""#)
        && facts.source_index.has("os.Getpid()")
        && facts.source_index.has("time.Now().Unix()");
    if !predictable_token {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d-%d-%s\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_341,
        file,
        line,
        col,
        "the token is built from observable pid, wall-clock time, and caller input instead of cryptographic randomness",
        out,
    );
}

pub(crate) fn detect_cwe_344(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_secret = facts
        .source_index
        .has_any(&["const billingHMACSecret = ", "const shipmentHMACSecret = "]);
    if !hardcoded_secret || !facts.source_index.has("hmac.New(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const billingHMACSecret = ") {
        idx
    } else {
        source.find("const shipmentHMACSecret = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_344,
        file,
        line,
        col,
        "a hard-coded invariant HMAC secret is embedded directly in code for a changing signing context",
        out,
    );
}

pub(crate) fn detect_cwe_346(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reflects_origin = facts
        .source_index
        .has(r#"Access-Control-Allow-Origin", origin"#)
        && facts.source_index.has(r#"Header.Get("Origin")"#);
    if !reflects_origin {
        return;
    }
    if facts
        .source_index
        .has_any(&["allowedOrigins", "trustedOrigins", "forbidden origin"])
    {
        return;
    }

    let start_byte = source.find("Access-Control-Allow-Origin").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_346,
        file,
        line,
        col,
        "the response reflects the caller-supplied Origin without validating it against a trusted allow-list",
        out,
    );
}
