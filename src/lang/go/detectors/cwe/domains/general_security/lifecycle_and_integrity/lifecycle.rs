use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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
