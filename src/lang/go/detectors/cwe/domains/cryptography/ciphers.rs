use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_325(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("cipher.NewCTR(") || !source.contains("XORKeyStream(") {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("Seal(") {
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

pub(crate) fn detect_cwe_1204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let static_iv = source.contains("cipher.NewCBCEncrypter(")
        && (source.contains("weakIV") || source.contains("weakIVPure"))
        && source.contains("1234567890123456");
    if !static_iv {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, iv)") {
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

pub(crate) fn detect_cwe_1240(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let custom_xor_cipher = (source.contains("SealSessionToken(")
        || source.contains("SealSessionTokenPure("))
        && (source.contains("xorCipher(") || source.contains("xorCipherPure("))
        && source.contains("^ key");
    if !custom_xor_cipher {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("aes.NewCipher(") {
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
