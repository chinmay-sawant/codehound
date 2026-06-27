use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_618(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

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

    let untrusted_plugin_path = facts.source_index.has("plugin.Open(")
        && (facts.source_index.has_any(&["module_path", "path := "]));
    if !untrusted_plugin_path {
        return;
    }
    if facts.source_index.has_any(&["allowedModules", "moduleRoot"]) {
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

    let wide_surface = (facts.source_index.has_any(&["MountWideSurface(", "MountWideSurfacePure("]))
        && (facts.source_index.has_any(&["/debug/pprof", "pprof.Index"]))
        && facts.source_index.has("/admin/sql")
        && facts.source_index.has("/admin/config")
        && facts.source_index.has("/internal/reload");
    if !wide_surface {
        return;
    }
    if facts.source_index.has_any(&["authRequired()", "authRequiredPure("]) {
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
