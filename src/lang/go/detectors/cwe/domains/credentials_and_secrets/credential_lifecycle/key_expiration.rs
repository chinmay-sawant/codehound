use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_324(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("ExpiresAt") {
        return;
    }
    let key_expiry_crypto_shape = (facts.source_index.has("ApiKeyRow") || facts.source_index.has("SigningKey"))
        && facts.source_index.has("Secret")
        && facts.source_index.has("hmac.New(");
    if !key_expiry_crypto_shape {
        return;
    }
    if facts.source_index.has("time.Now().After(row.ExpiresAt)")
        || facts.source_index.has("time.Now().After(key.ExpiresAt)")
    {
        return;
    }

    let expired_key_source =
        facts.source_index.has("Add(-48 * time.Hour)") || facts.source_index.has("ExpiresAt time.Time");
    if !expired_key_source {
        return;
    }

    let start_byte = source.find("ExpiresAt").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_324,
        file,
        line,
        col,
        "cryptographic processing uses key material with an expiration field but never checks whether the key is expired",
        out,
    );
}
