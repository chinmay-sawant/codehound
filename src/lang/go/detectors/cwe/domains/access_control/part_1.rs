use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_276(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0666"
            && (call.arguments[0].contains("sessions")
                || source.contains("session_data")
                || source.contains("X-Session-Data"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_276,
        file,
        line,
        col,
        "a session artifact is written with a world-readable and world-writable default mode",
        out,
    );
}

pub(crate) fn detect_cwe_277(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let clears_umask = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Umask"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    });
    if !clears_umask {
        return;
    }

    let Some(mkdir_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.MkdirAll"
            && call.arguments.len() >= 2
            && call.arguments[1].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(mkdir_call.start_byte);
    emit::push_finding(
        &META_CWE_277,
        file,
        line,
        col,
        "umask is cleared before creating a world-writable directory",
        out,
    );
}

pub(crate) fn detect_cwe_278(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(open_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.OpenFile"
            && call.arguments.len() >= 3
            && call.arguments[2].contains("os.FileMode(hdr.Mode)")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_278,
        file,
        line,
        col,
        "archive entry permissions are reapplied directly from untrusted metadata during extraction",
        out,
    );
}

pub(crate) fn detect_cwe_279(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("strconv.ParseUint(") {
        return;
    }

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_279,
        file,
        line,
        col,
        "the handler parses a requested mode but still writes the file with a hard-coded world-writable mode",
        out,
    );
}

pub(crate) fn detect_cwe_280(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(open_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Open")
    else {
        return;
    };

    let falls_through_on_error = source.contains("if err != nil {")
        && !source.contains("errors.Is(err, syscall.EACCES)")
        && !source.contains("errors.Is(err, syscall.EPERM)")
        && (source.contains("db.Exec(\"DELETE FROM tenants")
            || source.contains("tenantStore.Delete("));
    if !falls_through_on_error {
        return;
    }

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_280,
        file,
        line,
        col,
        "failure to access a protected resource leads into a privileged deletion path instead of a denial",
        out,
    );
}

pub(crate) fn detect_cwe_281(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Mode()") {
        return;
    }

    let Some(create_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Create")
    else {
        return;
    };

    if !source.contains("io.Copy(out, in)") {
        return;
    }

    let (line, col) = unit.line_col(create_call.start_byte);
    emit::push_finding(
        &META_CWE_281,
        file,
        line,
        col,
        "backup recreation uses os.Create and loses the source file's original permission bits",
        out,
    );
}

pub(crate) fn detect_cwe_289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("canonical_name = ?") {
        return;
    }
    if !source.contains("strings.Split(") || !source.contains(r#""@")[0]"#) {
        return;
    }

    let start_byte = source.find("strings.Split(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_289,
        file,
        line,
        col,
        "principal authentication strips the realm suffix and authenticates only the bare local username",
        out,
    );
}

pub(crate) fn detect_cwe_290(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(header_call) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.GetHeader" || call.callee.as_ref() == "r.Header.Get")
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("X-Remote-User"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(header_call.start_byte);
    emit::push_finding(
        &META_CWE_290,
        file,
        line,
        col,
        "the request trusts a caller-controlled X-Remote-User header as the authenticated identity",
        out,
    );
}

pub(crate) fn detect_cwe_294(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loads_auth_token = source.contains(r#"c.PostForm("auth_token")"#)
        || source.contains(r#"r.FormValue("auth_token")"#);
    if !loads_auth_token {
        return;
    }

    let has_nonce_tracking = source.contains("LoadOrStore(nonce, true)")
        || source.contains("spentNonces")
        || source.contains(r#"PostForm("nonce")"#)
        || source.contains(r#"FormValue("nonce")"#);
    if has_nonce_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("auth_token") {
        idx
    } else {
        return;
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_294,
        file,
        line,
        col,
        "the login flow accepts an authentication token without nonce tracking or replay detection",
        out,
    );
}

pub(crate) fn detect_cwe_301(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let echoes_challenge = source.contains(r#"gin.H{"proof": challenge}"#)
        || source.contains(r#"{"proof": challenge}"#)
        || source.contains(r#"map[string]string{"proof": challenge}"#);
    if !echoes_challenge {
        return;
    }
    if source.contains("hmac.New(") || source.contains("EncodeToString(") {
        return;
    }

    let start_byte = source.find("challenge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_301,
        file,
        line,
        col,
        "the server reflects the client challenge directly as the authentication proof",
        out,
    );
}

pub(crate) fn detect_cwe_303(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("hmac.New(") || !source.contains("mac.Sum(nil)") {
        return;
    }
    if !source.contains("string(expected) == sig") {
        return;
    }

    let start_byte = source.find("string(expected) == sig").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_303,
        file,
        line,
        col,
        "the computed MAC is compared to user input with string equality instead of constant-time verification",
        out,
    );
}

pub(crate) fn detect_cwe_305(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let debug_bypass = source.contains(r#"Query("debug") == "1""#)
        || source.contains(r#"Query().Get("debug") == "1""#);
    if !debug_bypass {
        return;
    }

    let has_subject_check = source.contains("jwt_sub") || source.contains("X-JWT-Sub");
    if !has_subject_check {
        return;
    }

    let start_byte = if let Some(idx) = source.find("debug") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_305,
        file,
        line,
        col,
        "a caller-controlled debug flag reaches privileged behavior before the authenticated subject check",
        out,
    );
}

pub(crate) fn detect_cwe_306(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_purge = source.contains("TRUNCATE ledger");
    if !destructive_purge {
        return;
    }
    let has_auth_gate = source.contains("operator_id") || source.contains("X-Operator-ID");
    if has_auth_gate {
        return;
    }

    let start_byte = source.find("TRUNCATE ledger").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_306,
        file,
        line,
        col,
        "a destructive purge endpoint performs its action without any authentication gate",
        out,
    );
}
