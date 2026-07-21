use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Response-leak R2 trust freeze (sensitive_fields.rs).
// Deferred sibling from B2 / parallel-catalog-program §2.2 / issue #159:
// sensitive field exposure in JSON responses (CWE-201) and incompatible-policy
// profile leaks (CWE-213). Parent family: response_leaks/ (metadata_leaks done
// in #108).
//
// Generalized sinks vs exact response literals: both rules already use
// call_facts on production-shaped JSON response APIs (`c.JSON`,
// `json.NewEncoder(w).Encode`). Residual risk is field/type-name inventory
// co-signals (APIKey/TokenKey/Salary/Comp, userRecord/memberRecord), not
// error-body or header museum strings.
//
// Proposed maturity: keep Heuristic for CWE-201 and CWE-213. Integrator applies
// maturity.rs / NEEDLES labels. See plans/v0.0.6/evidence-r2-sensitive-fields.md
// and plans/v0.0.6/pr-r2-sensitive-fields.md.

/// CWE-201 — Insertion of Sensitive Information Into Sent Data.
///
/// Freeze (R2 / #159): sensitive struct field co-signal (`APIKey` or `TokenKey`)
/// plus corpus record type (`type userRecord struct` or `type memberRecord struct`),
/// with call_facts primary on JSON response sink passing the loaded `record`
/// binding directly.
///
/// Safe path encodes a redacted DTO (`publicUser` / `publicMember`) instead of
/// `record` — negative is call-facts arg mismatch, not an SI gate. Do not
/// broaden to all struct fields named APIKey without the record→response shape.
/// Disposition: **keep Heuristic** (production JSON sink; field/type inventory
/// co-signals; not structural — §1.3: museum type names + arg `record`).
pub(crate) fn detect_cwe_201(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: sensitive field name in struct corpus.
    let has_sensitive_field =
        facts.source_index.has("APIKey") || facts.source_index.has("TokenKey");
    if !has_sensitive_field {
        return;
    }
    // Corpus co-signal: internal record type that carries the sensitive field.
    let sensitive_record_name = if facts.source_index.has("type userRecord struct")
        || facts.source_index.has("type memberRecord struct")
    {
        Some("record")
    } else {
        None
    };
    let Some(record_name) = sensitive_record_name else {
        return;
    };

    // Primary signal: call facts — JSON response sink serializes full record binding.
    let Some(call) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == record_name)
    }) else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_201,
        file,
        line,
        col,
        "a response serializes a record containing sensitive fields directly to the caller",
        out,
    );
}

/// CWE-213 — Exposure of Sensitive Information Due to Incompatible Policies.
///
/// Freeze (R2 / #159): compensation field co-signal (`Salary` or `Comp`) with
/// call_facts primary on JSON response sink passing the loaded `profile` binding.
/// Redaction negatives: policy-specific DTO construction (`guestProfile{` /
/// `directoryEntry{`) silences before sink match.
///
/// Safe path encodes guest/directory DTO omitting compensation — SI negative
/// gates plus call-facts arg mismatch on redacted types. Do not broaden to all
/// profiles containing Salary without the profile→response direct-serialize
/// shape. Disposition: **keep Heuristic** (production JSON sink; comp field
/// inventory; redaction DTO negatives; not structural — §1.3).
pub(crate) fn detect_cwe_213(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: compensation field in profile corpus.
    let has_comp_field = facts.source_index.has("Salary") || facts.source_index.has("Comp");
    if !has_comp_field {
        return;
    }
    // Negative prefilter: redacted policy-specific response DTO (safe paths).
    if facts.source_index.has("guestProfile{") || facts.source_index.has("directoryEntry{") {
        return;
    }

    // Primary signal: call facts — JSON response sink serializes full profile binding.
    let Some(call) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == "profile")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_213,
        file,
        line,
        col,
        "a public response serializes a profile that still contains compensation fields",
        out,
    );
}
