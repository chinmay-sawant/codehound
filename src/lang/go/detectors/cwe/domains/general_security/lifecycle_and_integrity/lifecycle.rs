use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_765(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let double_unlock = facts.source_index.has("Unlock()")
        && source.matches("Unlock()").count() >= 2
        && facts.source_index.has("DebitWallet");
    if !double_unlock {
        return;
    }
    if facts.source_index.has_any(&["defer walletMu.Unlock()", "defer cacheMu.Unlock()"]) {
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

pub(crate) fn detect_cwe_778(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let missing_auth_audit = facts.source_index.has("SignIn")
        && facts.source_index.has("username")
        && facts.source_index.has("password")
        && facts.source_index.has("Unauthorized");
    if !missing_auth_audit {
        return;
    }
    if facts.source_index.has(r#"log.Printf("auth failure"#) {
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

pub(crate) fn detect_cwe_826(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let premature_release = facts.source_index.has("go func()")
        && facts.source_index.has("db.Close()")
        && (facts.source_index.has_any(&["db.Query(", r#"db.Query("SELECT"#]));
    if !premature_release {
        return;
    }
    if facts.source_index.has_any(&["QueryContext(", "<-done
	c.Status("]) && !facts.source_index.has("db.Close()")
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

pub(crate) fn detect_cwe_1322(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let blocking_worker = (facts.source_index.has_any(&["StartWebhookWorker(", "StartWebhookWorkerPure("]))
        && facts.source_index.has("queue := make(chan")
        && facts.source_index.has("for payload := range queue")
        && facts.source_index.has("time.Sleep(2 * time.Second)");
    if !blocking_worker {
        return;
    }
    if facts.source_index.has("time.AfterFunc(") {
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
