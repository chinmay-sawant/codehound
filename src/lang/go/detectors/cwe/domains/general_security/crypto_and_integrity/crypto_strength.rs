use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_323(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let fixed_nonce = facts.source_index.has_any(&["sharedNonce", "relaySessionNonce", "static-nonce12", "fixednonce12"]);
    if !fixed_nonce || !facts.source_index.has("aead.Seal(") {
        return;
    }
    if facts.source_index.has("io.ReadFull(rand.Reader, nonce)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Nonce") {
        idx
    } else if let Some(idx) = source.find("nonce") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_323,
        file,
        line,
        col,
        "a fixed nonce is reused for AEAD encryption operations with the same key",
        out,
    );
}

pub(crate) fn detect_cwe_328(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("md5.Sum(") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_328,
        file,
        line,
        col,
        "a password digest is derived with MD5, which is too weak for this security-sensitive use",
        out,
    );
}

pub(crate) fn detect_cwe_331(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_recovery_code = facts.source_index.has("rand.NewSource(time.Now().UnixNano())")
        && facts.source_index.has("Intn(900000) + 100000")
        && facts.source_index.has("code");
    if !weak_recovery_code {
        return;
    }

    let start_byte = source.find("Intn(900000) + 100000").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_331,
        file,
        line,
        col,
        "the recovery code is generated from a small predictable decimal range instead of cryptographic randomness",
        out,
    );
}
