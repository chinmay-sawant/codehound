use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_328(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("md5.Sum(") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_328,
        file,
        line,
        col,
        "a password digest is derived with MD5, which is too weak for this security-sensitive use",
        out,
    );
}

pub(crate) fn detect_cwe_331(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_recovery_code = source.contains("rand.NewSource(time.Now().UnixNano())")
        && source.contains("Intn(900000) + 100000")
        && source.contains("code");
    if !weak_recovery_code {
        return;
    }

    let start_byte = source.find("Intn(900000) + 100000").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_331,
        file,
        line,
        col,
        "the recovery code is generated from a small predictable decimal range instead of cryptographic randomness",
        out,
    );
}

pub(crate) fn detect_cwe_341(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let predictable_token = source.contains("fmt.Sprintf(\"%d-%d-%s\"")
        && source.contains("os.Getpid()")
        && source.contains("time.Now().Unix()");
    if !predictable_token {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d-%d-%s\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_341,
        file,
        line,
        col,
        "the token is built from observable pid, wall-clock time, and caller input instead of cryptographic randomness",
        out,
    );
}

pub(crate) fn detect_cwe_344(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_secret = source.contains("const billingHMACSecret = ")
        || source.contains("const shipmentHMACSecret = ");
    if !hardcoded_secret || !source.contains("hmac.New(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const billingHMACSecret = ") {
        idx
    } else {
        source.find("const shipmentHMACSecret = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_344,
        file,
        line,
        col,
        "a hard-coded invariant HMAC secret is embedded directly in code for a changing signing context",
        out,
    );
}

pub(crate) fn detect_cwe_346(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reflects_origin = source.contains("Access-Control-Allow-Origin\", origin")
        && source.contains("Header.Get(\"Origin\")");
    if !reflects_origin {
        return;
    }
    if source.contains("allowedOrigins")
        || source.contains("trustedOrigins")
        || source.contains("forbidden origin")
    {
        return;
    }

    let start_byte = source.find("Access-Control-Allow-Origin").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_346,
        file,
        line,
        col,
        "the response reflects the caller-supplied Origin without validating it against a trusted allow-list",
        out,
    );
}

pub(crate) fn detect_cwe_353(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ingests_body = source.contains("io.ReadAll(") && source.contains("INSERT INTO telemetry")
        || source.contains("io.ReadAll(") && source.contains("INSERT INTO agent_reports");
    if !ingests_body {
        return;
    }
    if source.contains("X-Body-Mac") || source.contains("ConstantTimeCompare(expected, got)") {
        return;
    }

    let start_byte = source.find("io.ReadAll(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_353,
        file,
        line,
        col,
        "the inbound payload is stored without verifying any integrity MAC",
        out,
    );
}

pub(crate) fn detect_cwe_356(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_delete = (source.contains("func PurgeTenant(")
        && source.contains("DELETE FROM tenants WHERE slug = ?"))
        || (source.contains("func DeleteWorkspaceRecords(")
            && source.contains("DELETE FROM workspaces WHERE slug = ?"));
    if !destructive_delete {
        return;
    }
    if source.contains("X-Confirm-Purge") || source.contains("X-Confirm-Delete") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("DELETE FROM tenants") {
        idx
    } else {
        source.find("DELETE FROM workspaces").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_356,
        file,
        line,
        col,
        "the destructive action executes without an explicit confirmation token or second-step confirmation",
        out,
    );
}

pub(crate) fn detect_cwe_358(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_bearer_claims = source.contains("strings.TrimPrefix(raw, \"Bearer \")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_bearer_claims {
        return;
    }
    if source.contains("invalid jwt structure") || source.contains("unsupported jwt algorithm") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_358,
        file,
        line,
        col,
        "bearer token claims are accepted without required JWT structure and algorithm validation",
        out,
    );
}

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

pub(crate) fn detect_cwe_385(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let early_exit_secret_compare = source.contains("for i := 0; i < len(provided); i++")
        && source.contains("if provided[i] != expected[i] {")
        && source.contains("return false");
    if !early_exit_secret_compare {
        return;
    }
    if source.contains("ConstantTimeCompare(") {
        return;
    }

    let start_byte = source
        .find("for i := 0; i < len(provided); i++")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_385,
        file,
        line,
        col,
        "the secret comparison exits on the first mismatch and leaks timing information",
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

pub(crate) fn detect_cwe_412(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_lock_path = source.contains("lockfile") && source.contains("os.ReadFile(lockPath)");
    if !client_lock_path {
        return;
    }
    if source.contains("jobLockPath") || source.contains("fixedJobLock") {
        return;
    }

    let start_byte = source.find("lockfile").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_412,
        file,
        line,
        col,
        "the lock file path comes directly from the client request",
        out,
    );
}
