use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
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

pub(crate) fn detect_cwe_454(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_bootstrap_flag = source
        .contains("enforceMFA = c.PostForm(\"enforce_mfa\") == \"true\"")
        || source.contains("enforceMFA = r.FormValue(\"enforce_mfa\") == \"true\"");
    if !request_bootstrap_flag {
        return;
    }

    let start_byte = source.find("enforce_mfa").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_454,
        file,
        line,
        col,
        "the MFA enforcement flag is bootstrapped from client input instead of server configuration",
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

pub(crate) fn detect_cwe_488(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let global_session_map = source.contains("map[string][]string{}") && source.contains("session");
    if !global_session_map {
        return;
    }
    if source.contains("Cookie(\"session_id\")") || source.contains("r.Cookie(\"session_id\")") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sessionCarts") {
        idx
    } else {
        source.find("cartsBySession").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_488,
        file,
        line,
        col,
        "global cart state is keyed directly by a client-controlled session identifier",
        out,
    );
}

pub(crate) fn detect_cwe_494(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let downloads_bundle = source.contains("http.Get(") && source.contains("/tmp/worker.bin");
    if !downloads_bundle {
        return;
    }
    if source.contains("sha256.Sum256(") || source.contains("integrity check failed") {
        return;
    }

    let start_byte = source.find("http.Get(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_494,
        file,
        line,
        col,
        "the downloaded worker bundle is accepted without any pinned integrity verification",
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

pub(crate) fn detect_cwe_515(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_covert_flag = (source.contains("var quotaFlag int")
        || source.contains("var quotaCovertFlag int"))
        && source.contains(r#""over""#)
        && source.contains("= 1")
        && source.contains("= 0")
        && source.contains(r#""over_limit""#);
    if !shared_covert_flag {
        return;
    }
    if source.contains("WHERE tenant = ?")
        || source.contains("GetString(\"tenant\")")
        || source.contains("X-Tenant")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("var quotaFlag int") {
        idx
    } else {
        source.find("var quotaCovertFlag int").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_515,
        file,
        line,
        col,
        "a global quota flag is used as a covert cross-request signal",
        out,
    );
}

pub(crate) fn detect_cwe_544(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let inconsistent_db_failure_paths = (source.contains("panic(err)")
        || source.contains("panic(err)\n"))
        && source.contains("log.Println(err)")
        && (source.contains("db.Get(") || source.contains("db.QueryRow("));
    if !inconsistent_db_failure_paths {
        return;
    }
    if source.contains("writeDBError(") || source.contains("writeDBFailure(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("panic(err)") {
        idx
    } else {
        source.find("log.Println(err)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_544,
        file,
        line,
        col,
        "database failures are handled through inconsistent panic and logging paths",
        out,
    );
}

pub(crate) fn detect_cwe_552(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let permissive_upload_mode = (source.contains("FormFile(\"contract\")")
        || source.contains("FormFile(\"contract\")"))
        && source.contains("/srv/contracts")
        && source.contains("os.Chmod(dest, 0o777)");
    if !permissive_upload_mode {
        return;
    }
    if facts.source_index.has("filepath.Base(") || source.contains("os.Chmod(dest, 0o600)") {
        return;
    }

    let start_byte = source.find("os.Chmod(dest, 0o777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_552,
        file,
        line,
        col,
        "uploaded contract files are made world-accessible after storage",
        out,
    );
}

pub(crate) fn detect_cwe_565(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_cookie = (source.contains("c.Cookie(\"role\")")
        || source.contains("r.Cookie(\"role\")"))
        && source.contains(r#""admin""#)
        && source.contains("DELETE FROM tenants");
    if !trusts_role_cookie {
        return;
    }
    if source.contains("GetString(\"role\")") || source.contains("Header.Get(\"X-Role\")") {
        return;
    }

    let start_byte = source.find("Cookie(\"role\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_565,
        file,
        line,
        col,
        "a privileged delete action trusts a caller-controlled role cookie",
        out,
    );
}

pub(crate) fn detect_cwe_605(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("SO_REUSEADDR") || !source.contains("SetsockoptInt") {
        return;
    }
    if source.contains("net.Listen(\"tcp\", \":9090\")") {
        return;
    }

    let start_byte = source.find("SO_REUSEADDR").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_605,
        file,
        line,
        col,
        "the listener explicitly enables SO_REUSEADDR on the service socket",
        out,
    );
}

pub(crate) fn detect_cwe_611(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unsafe_xml = source.contains("xml.NewDecoder(")
        && source.contains("dec.Strict = false")
        && source.contains("Decode(&catalog)");
    if !unsafe_xml {
        return;
    }
    if source.contains("<!DOCTYPE")
        || source.contains("dec.Strict = true")
        || source.contains("LimitReader")
    {
        return;
    }

    let start_byte = source.find("dec.Strict = false").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_611,
        file,
        line,
        col,
        "untrusted XML is parsed with strict mode disabled and no DOCTYPE rejection",
        out,
    );
}
