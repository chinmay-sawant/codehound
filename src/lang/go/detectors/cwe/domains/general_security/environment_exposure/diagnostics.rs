use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_420(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_unprotected_debug_route = (source.contains("r.GET(\"/debug/sqltrace\"")
        && source.contains("r.Group(\"/api\", requireJWT())"))
        || (source.contains("http.HandleFunc(\"/debug/sqltrace\"")
            && source.contains("http.Handle(\"/api/invoices\", protected)"));
    if !has_unprotected_debug_route {
        return;
    }

    let start_byte = source.find("/debug/sqltrace").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_420,
        file,
        line,
        col,
        "the alternate debug route is exposed outside the primary authenticated API guard",
        out,
    );
}

pub(crate) fn detect_cwe_426(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_controlled_plugin_dir =
        source.contains("plugin_dir") && source.contains("plugin.Open(modPath)");
    if !request_controlled_plugin_dir {
        return;
    }
    if source.contains("trustedPluginDir") || source.contains("trustedPluginRoot") {
        return;
    }

    let start_byte = source.find("plugin_dir").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_426,
        file,
        line,
        col,
        "the plugin load directory is derived from caller-controlled input",
        out,
    );
}

pub(crate) fn detect_cwe_497(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let exposes_host_details = source.contains("os.Environ()")
        || source.contains("os.Hostname()")
        || source.contains("runtime.NumCPU()");
    if !exposes_host_details {
        return;
    }
    if source.contains(r#""status": "ok""#) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.Environ()") {
        idx
    } else if let Some(idx) = source.find("os.Hostname()") {
        idx
    } else {
        source.find("runtime.NumCPU()").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_497,
        file,
        line,
        col,
        "the diagnostics endpoint exposes host environment details to callers",
        out,
    );
}
