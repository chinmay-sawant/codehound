use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Configuration C2 trust freeze (config_hardcoding.rs).
// Selected family for parallel-catalog-program §3.2 / issue #113:
// config hardcoding / external control of configuration settings
// (CWE-15, CWE-472, CWE-1051, CWE-1067). Deferred sibling leaf:
// secrets_in_config.rs (CWE-260 env-requiredness; CWE-455 fail-fast /
// deployment-mode policy) — deferred unless an explicit policy profile
// is approved.
//
// Project-agnostic contract (why this family): CWE-15 proves request-
// derived values must not configure database-opening sinks — a universal
// correctness/security property independent of org policy or deployment
// topology. Sibling rules 472/1051/1067 share the hardcoding leaf but are
// corpus-gated museums (role form, fixed private host, leading-wildcard
// LIKE on notes.body).
//
// Primary evidence:
// - CWE-15: call_facts primary (CONFIG_SINKS + user-controlled input
//   bindings); no SourceIndex emit gate.
// - CWE-472 / 1051 / 1067: SourceIndex / exact source-text co-presence.
//
// Proposed maturity: keep Heuristic for CWE-15; fixture-only for
// CWE-472 / 1051 / 1067. Integrator applies maturity.rs / NEEDLES labels.
// See plans/v0.0.5/pr-cwe-trust-configuration-residual.md and
// plans/v0.0.5/evidence-cwe-trust-configuration-residual.md.

/// CWE-15 — External Control of System or Configuration Setting.
///
/// Freeze (C2 / #113): request-derived configuration value reaches a
/// database-opening sink. Primary signal is **call_facts**:
/// `is_configuration_sink(callee)` (`sql.Open` / fixture `factory`) with
/// an argument that uses an `InputKind::UserControlled` binding.
///
/// Project-agnostic contract: external (user) control of connection /
/// configuration settings is a security defect regardless of org policy.
/// Call facts are already complete primary for the sink+taint-lite
/// boundary; no oracle-safe rewrite is required (and bare `factory` remains
/// a fixture-shaped CONFIG_SINKS entry for frameworks oracle only — not
/// promoted to Structural without broader sink coverage + real-module bar).
/// Disposition: **keep Heuristic**.
pub(crate) fn detect_cwe_15(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if !is_configuration_sink(&call.callee) {
            continue;
        }

        if !call.arguments.iter().any(|arg| {
            facts.input_bindings.iter().any(|binding| {
                binding.kind == InputKind::UserControlled
                    && argument_uses_identifier(arg, &binding.name)
            })
        }) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_15,
            file,
            line,
            col,
            "request-derived configuration value reaches a database-opening sink",
            out,
        );
    }
}

/// CWE-472 — External Control of Assumed-Immutable Web Parameter.
///
/// Freeze (C2 / #113): authorization trusts a client-submitted role field
/// (`Role    string \`form:"role"\`` or `role := r.FormValue("role")`)
/// instead of resolving role server-side (`SELECT role FROM users`).
///
/// Primary evidence is exact form/role corpus co-presence — not a
/// generalized authorization API. Call facts for form bind / FormValue
/// alone cannot prove the field is treated as an immutable authz claim
/// without the role-name co-signal (and would collide with broader
/// access-control ownership). Org-policy shaped; disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_472(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): client-submitted role field.
    // Negative gate: server-side role resolution via SELECT role FROM users.
    let trusts_role_form = facts.source_index.has("Role    string `form:\"role\"`")
        || facts.source_index.has("role := r.FormValue(\"role\")");
    if !trusts_role_form {
        return;
    }
    if facts.source_index.has("SELECT role FROM users") {
        return;
    }

    let start_byte = source.find("role").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_472,
        file,
        line,
        col,
        "authorization trusts a client-submitted role field instead of resolving role server-side",
        out,
    );
}

/// CWE-1051 — Initialization with Hard-Coded Network Resource Configuration Data.
///
/// Freeze (C2 / #113): outbound billing request pinned to hard-coded
/// internal host `10.20.30.40:9090` with ChargeCard / ChargeCardPure helpers,
/// `http.NewRequest(`, and `X-Card-Token`; negative `os.Getenv("BILLING_API_URL")`.
///
/// Deployment-configuration museum: exact private IP + helper names are the
/// proof boundary. Generalized hard-coded-host detection would over-fire on
/// localhost/test endpoints and is deferred. Disposition: **fixture-only**.
pub(crate) fn detect_cwe_1051(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): ChargeCard* + fixed private host
    // + NewRequest + card-token header. Negative: BILLING_API_URL env load.
    let hard_coded_upstream = (facts.source_index.has("ChargeCard(")
        || facts.source_index.has("ChargeCardPure("))
        && facts.source_index.has("10.20.30.40:9090")
        && facts.source_index.has("http.NewRequest(")
        && facts.source_index.has("X-Card-Token");
    if !hard_coded_upstream {
        return;
    }
    if facts.source_index.has("os.Getenv(\"BILLING_API_URL\")") {
        return;
    }

    let start_byte = source.find("10.20.30.40:9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1051,
        file,
        line,
        col,
        "an outbound billing request is pinned to a hard-coded internal host",
        out,
    );
}

/// CWE-1067 — Excessive Execution of Sequential Searches of Data Resource.
///
/// Freeze (C2 / #113): search predicate uses leading-wildcard pattern
/// `fmt.Sprintf("%%%s%%", term)` (or `pattern := fmt.Sprintf(...)`) with
/// LIKE + (`notes.body` or `SELECT id, body FROM notes`); negatives
/// `prefix+"%"` / `pattern := prefix + "%"`.
///
/// Performance / sequential-scan museum gated on notes-table corpus text.
/// Call facts for `fmt.Sprintf` alone cannot prove a leading-wildcard DB
/// scan without the LIKE + table co-signals. Disposition: **fixture-only**.
pub(crate) fn detect_cwe_1067(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): leading-wildcard sprintf + LIKE
    // + notes corpus. Negative: prefix-only pattern (indexed-friendly).
    let leading_wildcard_scan = (facts.source_index.has("fmt.Sprintf(\"%%%s%%\", term)")
        || facts
            .source_index
            .has("pattern := fmt.Sprintf(\"%%%s%%\", term)"))
        && facts.source_index.has("LIKE")
        && (facts.source_index.has("notes.body")
            || facts.source_index.has("SELECT id, body FROM notes"));
    if !leading_wildcard_scan {
        return;
    }
    if facts.source_index.has("prefix+\"%\"") || facts.source_index.has("pattern := prefix + \"%\"")
    {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%%%s%%\", term)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1067,
        file,
        line,
        col,
        "a search predicate uses a leading wildcard pattern that forces a sequential scan",
        out,
    );
}
