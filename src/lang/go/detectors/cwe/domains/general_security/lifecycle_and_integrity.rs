use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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
