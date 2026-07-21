use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-93 — Improper Neutralization of CRLF Sequences in HTTP Headers.
///
/// Freeze (C1 / #112): non-taint injection residual. Primary evidence is
/// already generalized facts — not SourceIndex corpus needles:
///
/// 1. `input_bindings` of kind `UserControlled`
/// 2. `call_facts` sink: `c.Header` or `w.Header().Set` with header name
///    `"Location"` and a value argument that uses the binding identifier
/// 3. Safe negative: both CR and LF stripped via `strings.ReplaceAll` on
///    the same binding (scratch_contains; not SI)
///
/// Does **not** duplicate taint-core ownership (CWE-22/78/79/89/90/91): those
/// rules own path/command/XSS/SQL/LDAP/XML sinks via the taint graph. CWE-93
/// is a local header-value CRLF boundary with an explicit sanitizer gate.
///
/// Disposition: **keep Structural** (already allow-listed). Proof boundary is
/// production-shaped Location-header write + user-controlled binding + CRLF
/// strip negative. Do not broaden to all header names without a reviewed
/// FP budget; do not convert to taint-core. Sibling `resource.rs`
/// (CWE-619 / CWE-917) is **fixture-only** under G3 / #139 (pure SI museums;
/// see `resource.rs` freeze).
pub(crate) fn detect_cwe_93(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    use crate::engine::scratch_contains;
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        // Safe negative: both CR and LF stripped on this binding before use.
        let strips_cr = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\r", "")"#,
        );
        let strips_lf = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\n", "")"#,
        );
        if strips_cr && strips_lf {
            continue;
        }

        // Primary signal: call facts — Location header write whose value
        // argument uses the user-controlled binding (single walk for proof + span).
        let Some(sink_call) = facts.call_facts.iter().find(|call| {
            matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
                && call.arguments.len() >= 2
                && call.arguments[0].as_ref() == r#""Location""#
                && argument_uses_identifier(&call.arguments[1], &binding.name)
        }) else {
            continue;
        };

        let (line, col) = unit.line_col(sink_call.start_byte);
        emit::push_finding(
            &META_CWE_93,
            file,
            line,
            col,
            "user-controlled input is concatenated into a Location header without CRLF stripping",
            out,
        );
    }
}
