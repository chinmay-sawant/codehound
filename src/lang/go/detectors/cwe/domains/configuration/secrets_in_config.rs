use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Configuration R1 trust freeze (secrets_in_config.rs).
// Selected deferred sibling from C2 / parallel-catalog-program §3.2 / issue #158:
// secrets-from-config env-requiredness (CWE-260) and fail-fast TLS startup
// policy (CWE-455). Parent family: configuration/ (CWE-15 deferred to
// config_hardcoding in #113).
//
// NOT project-agnostic: both rules encode org/deployment policy museums —
// "secrets must come from environment" (260) and "startup must abort when
// security TLS material fails" (455). Without an approved policy profile,
// these are corpus-gated fixtures only, not universal correctness sinks.
//
// Primary evidence: SourceIndex / exact source-text co-presence for both rules.
// Call facts cannot prove env-requiredness or fail-fast policy without
// over-firing (any config-file secret load; any TLS error log without Fatalf).
//
// Proposed maturity: fixture-only for CWE-260 and CWE-455. Integrator applies
// maturity.rs / NEEDLES labels. See plans/v0.0.6/evidence-r1-secrets-in-config.md
// and plans/v0.0.6/pr-r1-secrets-in-config.md.

/// CWE-260 — Password in Configuration File.
///
/// Freeze (R1 / #158): secret-bearing config struct field
/// (`Password string` / `Secret   string`) with direct use of loaded secret
/// (`cfg.Password` / `cfg.Secret`) and no `os.Getenv(` anywhere in unit.
///
/// Environment-requiredness museum: org policy that credentials must not live
/// in on-disk config is not a project-agnostic security contract (many
/// deployments use sealed config files, secret managers, or sidecars). SI
/// primary with exact field-name corpus; safe fixtures omit secret struct
/// fields (frameworks/stdlib) or load via `os.Getenv(` (negative gate).
/// Call facts for `os.ReadFile` + struct unmarshal cannot distinguish
/// secret vs non-secret fields without the museum co-signals. Disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_260(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): secret-bearing config type field.
    let config_type_has_secret_field =
        facts.source_index.has("Password string") || facts.source_index.has("Secret   string");
    if !config_type_has_secret_field {
        return;
    }
    // Negative gate: any env load silences (env-requiredness safe path).
    if facts.source_index.has("os.Getenv(") {
        return;
    }
    // Primary signal (fixture-literal / SI): loaded secret used from cfg.*
    if !(facts.source_index.has("cfg.Password") || facts.source_index.has("cfg.Secret")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("cfg.Password") {
        idx
    } else {
        source.find("cfg.Secret").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_260,
        file,
        line,
        col,
        "a secret-bearing field is loaded from a configuration file and used directly",
        out,
    );
}

/// CWE-455 — Non-Existent Resource Reference (fail-fast / deployment policy).
///
/// Freeze (R1 / #158): TLS material load failure logged with exact corpus text
/// `continuing without mTLS` after `tls.LoadX509KeyPair(` without `log.Fatalf(`.
///
/// Fail-fast / deployment-mode museum: whether a service must abort startup
/// when optional mTLS/HSM material is unavailable is org/deployment policy,
/// not a universal correctness property (degraded mode, health-only endpoints,
/// retry-at-init patterns). SI primary with exact log substring + TLS load
/// co-signal; negative `log.Fatalf(` for required-at-startup safe path.
/// Call facts for `tls.LoadX509KeyPair` + error handling cannot prove
/// policy without over-firing on every non-Fatal TLS error path. Disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_455(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): TLS load + exact continue log text.
    let continues_after_tls_failure = facts.source_index.has("tls.LoadX509KeyPair(")
        && facts.source_index.has("continuing without mTLS");
    if !continues_after_tls_failure {
        return;
    }
    // Negative gate: fatal exit on TLS load failure (fail-fast safe path).
    if facts.source_index.has("log.Fatalf(") {
        return;
    }

    let start_byte = source.find("continuing without mTLS").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_455,
        file,
        line,
        col,
        "startup logs a TLS material failure but continues running anyway",
        out,
    );
}
