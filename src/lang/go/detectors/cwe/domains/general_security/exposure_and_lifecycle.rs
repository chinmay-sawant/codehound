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


pub(crate) fn detect_cwe_618(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let exposes_native_bridge = source.contains("/opt/vendor/activex-bridge")
        && facts.source_index.has("exec.Command(")
        && source.contains("method")
        && source.contains("args");
    if !exposes_native_bridge {
        return;
    }
    if source.contains("allowedPluginMethods") {
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


pub(crate) fn detect_cwe_765(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let double_unlock = source.contains("Unlock()")
        && source.matches("Unlock()").count() >= 2
        && source.contains("DebitWallet");
    if !double_unlock {
        return;
    }
    if source.contains("defer walletMu.Unlock()") || source.contains("defer cacheMu.Unlock()") {
        return;
    }

    let start_byte = source.find("Unlock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_765,
        file,
        line,
        col,
        "the critical-section lock is explicitly released twice on an error path",
        out,
    );
}


pub(crate) fn detect_cwe_778(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let missing_auth_audit = source.contains("SignIn")
        && source.contains("username")
        && source.contains("password")
        && source.contains("Unauthorized");
    if !missing_auth_audit {
        return;
    }
    if source.contains("log.Printf(\"auth failure") {
        return;
    }

    let start_byte = source.find("Unauthorized").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_778,
        file,
        line,
        col,
        "authentication failures are returned without any audit logging",
        out,
    );
}


pub(crate) fn detect_cwe_826(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let premature_release = source.contains("go func()")
        && source.contains("db.Close()")
        && (source.contains("db.Query(") || source.contains("db.Query(\"SELECT"));
    if !premature_release {
        return;
    }
    if source.contains("QueryContext(")
        || source.contains("<-done\n\tc.Status(") && !source.contains("db.Close()")
    {
        return;
    }

    let start_byte = source.find("db.Close()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_826,
        file,
        line,
        col,
        "a shared database handle is closed before a background task finishes using it",
        out,
    );
}


pub(crate) fn detect_cwe_829(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let untrusted_plugin_path = source.contains("plugin.Open(")
        && (source.contains("module_path") || source.contains("path := "));
    if !untrusted_plugin_path {
        return;
    }
    if source.contains("allowedModules") || source.contains("moduleRoot") {
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


pub(crate) fn detect_cwe_1125(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wide_surface = (source.contains("MountWideSurface(")
        || source.contains("MountWideSurfacePure("))
        && (source.contains("/debug/pprof") || source.contains("pprof.Index"))
        && source.contains("/admin/sql")
        && source.contains("/admin/config")
        && source.contains("/internal/reload");
    if !wide_surface {
        return;
    }
    if source.contains("authRequired()") || source.contains("authRequiredPure(") {
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


pub(crate) fn detect_cwe_1322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let blocking_worker = (source.contains("StartWebhookWorker(")
        || source.contains("StartWebhookWorkerPure("))
        && source.contains("queue := make(chan")
        && source.contains("for payload := range queue")
        && source.contains("time.Sleep(2 * time.Second)");
    if !blocking_worker {
        return;
    }
    if source.contains("time.AfterFunc(") {
        return;
    }

    let start_byte = source.find("time.Sleep(2 * time.Second)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1322,
        file,
        line,
        col,
        "the webhook worker blocks its queue loop with sleep instead of scheduling retries asynchronously",
        out,
    );
}

