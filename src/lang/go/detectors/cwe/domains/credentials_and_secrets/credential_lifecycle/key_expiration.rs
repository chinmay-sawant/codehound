use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Credential-lifecycle R5 trust freeze (key_expiration.rs).
// Bounded family leaf: CWE-324 (~41 lines). Sibling leaf password_aging.rs
// (CWE-262/263) is selected in the same R5 slice — combined ~94 lines.
// Primary evidence is SourceIndex corpus co-presence (ExpiresAt + key row
// types + hmac.New), not call_facts/AST. Field/type names are policy evidence.
// Proposed maturity: fixture-only (integrator applies maturity.rs).
// See plans/v0.0.6/evidence-r5-credential-expiration.md and
// pr-r5-credential-expiration.md. Deferred sibling: reset_recovery.rs (R6).

/// CWE-324 — Use of a Key Past its Expiration Date.
///
/// Freeze (R5 / #162): SI `ExpiresAt` with (`ApiKeyRow` or `SigningKey`),
/// `Secret`, and `hmac.New(`, without `time.Now().After(row.ExpiresAt)` or
/// `time.Now().After(key.ExpiresAt)`, plus expired-key museum source
/// (`Add(-48 * time.Hour)` or `ExpiresAt time.Time`).
///
/// Runtime/deployment assumption: expiration may be enforced outside this
/// unit (gateway, KMS rotation, remote key service). Call facts for
/// `hmac.New` alone fire on every legitimate MAC path and cannot prove
/// "key past expiry" without the corpus ExpiresAt + row-type co-signals.
/// Disposition: **fixture-only**.
pub(crate) fn detect_cwe_324(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): ExpiresAt field present with crypto
    // key-row museum shape (ApiKeyRow|SigningKey + Secret + hmac.New().
    // Negative gate: time.Now().After(row|key.ExpiresAt).
    // Expired-key source gate: Add(-48 * time.Hour) or ExpiresAt time.Time.
    if !facts.source_index.has("ExpiresAt") {
        return;
    }
    let key_expiry_crypto_shape = (facts.source_index.has("ApiKeyRow")
        || facts.source_index.has("SigningKey"))
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

    let expired_key_source = facts.source_index.has("Add(-48 * time.Hour)")
        || facts.source_index.has("ExpiresAt time.Time");
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
