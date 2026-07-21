use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-502: untrusted gob deserialization into a privileged action shape.
///
/// Evidence freeze (A3 / #98):
/// - Primary sink proof: `call_facts` callee `gob.NewDecoder` (stdlib constructor).
/// - Corpus co-signals (non-primary, oracle gates): `adminAction`, `Grant`,
///   exact `.Decode(&action)` target.
/// - SI impossibility prefilter: `gob.NewDecoder(` (+ historical `encoding/gob`).
/// - Safe negatives: validated JSON bind paths
///   (`ShouldBindJSON(&req)`, `json.NewDecoder(r.Body).Decode(&req)`).
/// - Out of scope: arbitrary `.Decode` without receiver proof / type-sensitive
///   decoder expansion (json/xml/yaml/etc.).
///
/// Disposition proposal for integrator: **fixture-only** (default maturity is
/// currently Heuristic via fallthrough — quarantine in `maturity.rs` only on
/// the integration branch). Not a generalized unsafe-deserialization boundary.
pub(crate) fn detect_cwe_502(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no gob decoder construction text ⇒ no sink.
    if !(facts.source_index.has("gob.NewDecoder(") || facts.source_index.has("encoding/gob")) {
        return;
    }

    // Corpus co-signals still required for oracle (admin-action privileged shape).
    // Without these, bare gob.NewDecoder would mass-FP legitimate gob codecs.
    // Maturity should be fixture-only; call_facts is the primary sink proof only.
    let admin_action_shape = facts.source_index.has("adminAction")
        && facts.source_index.has("Grant")
        && facts.source_index.has(".Decode(&action)");
    if !admin_action_shape {
        return;
    }

    // Negative prefilters: validated JSON bind paths (corpus safe fixtures).
    if facts.source_index.has("ShouldBindJSON(&req)")
        || facts
            .source_index
            .has("json.NewDecoder(r.Body).Decode(&req)")
    {
        return;
    }

    // Primary signal: call facts — stdlib gob.NewDecoder construction.
    // Do not treat arbitrary Decode methods as unsafe without receiver proof.
    let Some(decoder_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "gob.NewDecoder")
    else {
        return;
    };

    let (line, col) = unit.line_col(decoder_call.start_byte);
    emit::push_finding(
        &META_CWE_502,
        file,
        line,
        col,
        "user-controlled gob data is deserialized into a privileged admin action",
        out,
    );
}
