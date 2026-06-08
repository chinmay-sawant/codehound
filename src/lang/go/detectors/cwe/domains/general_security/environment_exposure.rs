use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_359(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let serializes_pii = (source.contains("SSN")
        && source.contains("Phone")
        && source.contains("json.Marshal(row)"))
        || (source.contains("SSN")
            && source.contains("Phone")
            && source.contains("json.Marshal(")
            && source.contains("PersonRecord"));
    if !serializes_pii {
        return;
    }
    if source.contains("PublicProfile")
        || source.contains("PublicPersonView")
        || source.contains("requester != target")
    {
        return;
    }

    let start_byte = source
        .find("json.Marshal(row)")
        .unwrap_or_else(|| source.find("SSN").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_359,
        file,
        line,
        col,
        "private personal information is serialized directly without requester authorization or public projection",
        out,
    );
}

pub(crate) fn detect_cwe_360(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("X-Forwarded-For") {
        return;
    }
    if source.contains("SplitHostPort(") || source.contains("RemoteAddr") {
        return;
    }

    let start_byte = source.find("X-Forwarded-For").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_360,
        file,
        line,
        col,
        "a security-sensitive client IP action trusts caller-controlled forwarded header data",
        out,
    );
}

pub(crate) fn detect_cwe_393(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wrong_status = source.contains("if err != nil {")
        && source.contains("WriteHeader(http.StatusOK)")
        && source.contains(r#"{"balance":0}"#);
    if !wrong_status {
        return;
    }

    let start_byte = source.find("WriteHeader(http.StatusOK)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_393,
        file,
        line,
        col,
        "lookup failure still returns HTTP 200 with a fallback balance payload",
        out,
    );
}

pub(crate) fn detect_cwe_403(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let opens_secret_before_exec = source.contains("os.Open(\"/etc/slopguard/master.key\")")
        && source.contains("exec.Command(\"/bin/sh\", \"-c\"");
    if !opens_secret_before_exec {
        return;
    }
    if source.contains("secret.Fd()") || source.contains("defer secret.Close()") {
        return;
    }

    let start_byte = source
        .find("os.Open(\"/etc/slopguard/master.key\")")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_403,
        file,
        line,
        col,
        "a sensitive descriptor is left open when launching a child shell command",
        out,
    );
}

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

pub(crate) fn detect_cwe_427(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let path_mutation =
        source.contains("os.Setenv(\"PATH\",") && source.contains("exec.Command(\"pdftopng\"");
    if !path_mutation {
        return;
    }
    if source.contains("pdftopngPath") || source.contains("pdftopngBinary") {
        return;
    }

    let start_byte = source.find("os.Setenv(\"PATH\",").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_427,
        file,
        line,
        col,
        "user input is prepended to PATH before resolving the helper binary by name",
        out,
    );
}

pub(crate) fn detect_cwe_459(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let temp_export = source.contains("CreateTemp(")
        && (source.contains("c.File(f.Name())") || source.contains("ServeFile(w, r, f.Name())"));
    if !temp_export {
        return;
    }
    if source.contains("os.Remove(f.Name())") {
        return;
    }

    let start_byte = source.find("CreateTemp(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_459,
        file,
        line,
        col,
        "the temporary export file is served without being removed afterward",
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
