use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Lifecycle/integrity R7 trust freeze (lifecycle_and_integrity/plugins.rs).
// Bounded subfamily: CWE-618, 829, 1125 (3 rules; whole leaf — ~92 lines).
// Primary evidence is SourceIndex corpus co-presence (vendor bridge path, plugin.Open
// + caller path, MountWideSurface + debug/admin/internal routes), not call_facts/AST.
// Vendor path literals, allowlist helper names, and mount helper names are policy
// evidence unless a stronger local proof exists — none does here.
// Proposed maturity: fixture-only for all three (integrator applies maturity.rs).
// Sibling leaves lifecycle.rs / runtime_state.rs deferred (topology / ownership /
// cross-request state). See plans/v0.0.6/evidence-r7-lifecycle-integrity.md.

pub(crate) fn detect_cwe_618(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact vendor native-bridge path
    // `/opt/vendor/activex-bridge` + exec.Command( + method/args query co-signals.
    // Negative gate: allowedPluginMethods allowlist.
    // Call-facts for exec.Command alone cannot prove ActiveX/native-bridge exposure
    // without the corpus vendor path; keep SI primary. Not a generalized exec detector.
    // Proposed: fixture-only.
    let exposes_native_bridge = facts.source_index.has("/opt/vendor/activex-bridge")
        && facts.source_index.has("exec.Command(")
        && facts.source_index.has("method")
        && facts.source_index.has("args");
    if !exposes_native_bridge {
        return;
    }
    if facts.source_index.has("allowedPluginMethods") {
        return;
    }

    let start_byte = source.find("/opt/vendor/activex-bridge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_618,
        file,
        line,
        col,
        "the endpoint forwards caller-controlled method names into a privileged native helper",
        out,
    );
}

pub(crate) fn detect_cwe_829(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): plugin.Open( + caller-controlled path markers
    // (module_path / path := ).
    // Negative gate: allowedModules / moduleRoot allowlist + fixed root.
    // Call-facts for plugin.Open alone fires on safe allowlisted loads; path-policy
    // proof is corpus SI. Keep SI primary. Not a generalized plugin-load detector.
    // Proposed: fixture-only.
    let untrusted_plugin_path = facts.source_index.has("plugin.Open(")
        && (facts.source_index.has_any(&["module_path", "path := "]));
    if !untrusted_plugin_path {
        return;
    }
    if facts
        .source_index
        .has_any(&["allowedModules", "moduleRoot"])
    {
        return;
    }

    let start_byte = source.find("plugin.Open(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_829,
        file,
        line,
        col,
        "a plugin is loaded from a caller-controlled filesystem path",
        out,
    );
}

pub(crate) fn detect_cwe_1125(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): MountWideSurface(|MountWideSurfacePure( +
    // exact debug/admin/internal route co-presence (/debug/pprof|pprof.Index,
    // /admin/sql, /admin/config, /internal/reload).
    // Negative gate: authRequired() / authRequiredPure( — authenticated minimal surface.
    // Route-set topology is not CFG-proven; museum mount helper + literal routes.
    // Keep SI primary. Not a generalized attack-surface analyzer.
    // Proposed: fixture-only.
    let wide_surface = (facts
        .source_index
        .has_any(&["MountWideSurface(", "MountWideSurfacePure("]))
        && (facts.source_index.has_any(&["/debug/pprof", "pprof.Index"]))
        && facts.source_index.has("/admin/sql")
        && facts.source_index.has("/admin/config")
        && facts.source_index.has("/internal/reload");
    if !wide_surface {
        return;
    }
    if facts
        .source_index
        .has_any(&["authRequired()", "authRequiredPure("])
    {
        return;
    }

    let start_byte = source.find("/debug/pprof").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1125,
        file,
        line,
        col,
        "public routing exposes debug, admin, and internal maintenance endpoints together",
        out,
    );
}
