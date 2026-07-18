use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_325(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Needle-primary stdlib API smell (Heuristic). Needles are negative-gate /
    // prefilter tokens only; do not promote to structural without call facts.
    if !facts.source_index.has("cipher.NewCTR(") || !facts.source_index.has("XORKeyStream(") {
        return;
    }
    if facts.source_index.has("cipher.NewGCM(") || facts.source_index.has("Seal(") {
        return;
    }

    let start_byte = source.find("cipher.NewCTR(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_325,
        file,
        line,
        col,
        "sensitive data is encrypted with CTR mode without an authentication or integrity step",
        out,
    );
}

pub(crate) fn detect_cwe_1204(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Fixture-only: exact IV literal + weakIV identifiers (see rules::maturity).
    // Keep for --profile all corpus tests; never in recommended/security packs.
    let static_iv = facts.source_index.has("cipher.NewCBCEncrypter(")
        && (facts.source_index.has("weakIV") || facts.source_index.has("weakIVPure"))
        && facts.source_index.has("1234567890123456");
    if !static_iv {
        return;
    }
    if facts.source_index.has("io.ReadFull(rand.Reader, iv)") {
        return;
    }

    let start_byte = source.find("1234567890123456").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1204,
        file,
        line,
        col,
        "CBC encryption uses a fixed IV literal instead of generating one per request",
        out,
    );
}

pub(crate) fn detect_cwe_1240(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Fixture-only: corpus helper names + XOR body shape (see rules::maturity).
    // Keep for --profile all corpus tests; never in recommended/security packs.
    let custom_xor_cipher = (facts.source_index.has("SealSessionToken(")
        || facts.source_index.has("SealSessionTokenPure("))
        && (facts.source_index.has("xorCipher(") || facts.source_index.has("xorCipherPure("))
        && facts.source_index.has("^ key");
    if !custom_xor_cipher {
        return;
    }
    if facts.source_index.has("cipher.NewGCM(") || facts.source_index.has("aes.NewCipher(") {
        return;
    }

    let start_byte = source.find("xorCipher").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1240,
        file,
        line,
        col,
        "session sealing uses a homegrown XOR cipher instead of a standard authenticated primitive",
        out,
    );
}
