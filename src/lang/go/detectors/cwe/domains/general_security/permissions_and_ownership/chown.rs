use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_648(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no os.Chown text ⇒ no privileged ownership sink.
    if !facts.source_index.has("os.Chown(") {
        return;
    }
    // Corpus co-signals still required for oracle (exact FormValue/PostForm keys for
    // path + uid). Maturity remains fixture-only; call_facts is the primary sink proof.
    let privileged_chown = facts.source_index.has("uid")
        && (facts
            .source_index
            .has_any(&[r#"PostForm("uid")"#, r#"FormValue("uid")"#]))
        && (facts
            .source_index
            .has_any(&[r#"PostForm("path")"#, r#"FormValue("path")"#]));
    if !privileged_chown {
        return;
    }
    // Negative prefilters: controlled upload root / service identity / privilege drop.
    if facts
        .source_index
        .has_any(&["uploadRoot", "spoolDir", "serviceUID", "Setuid("])
    {
        return;
    }

    // Primary signal: call facts — stdlib `os.Chown` callee.
    let Some(chown_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Chown")
    else {
        return;
    };

    let (line, col) = unit.line_col(chown_call.start_byte);
    emit::push_finding(
        &META_CWE_648,
        file,
        line,
        col,
        "the handler passes caller-controlled values into a privileged ownership-change API",
        out,
    );
}

pub(crate) fn detect_cwe_708(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no os.Chown text ⇒ no ownership-assignment sink.
    if !facts.source_index.has("os.Chown(") {
        return;
    }
    // Corpus co-signals still required for oracle (owner_uid identifier + dest form key).
    // Maturity remains fixture-only; call_facts is the primary sink proof.
    let caller_chosen_owner = facts.source_index.has("owner_uid")
        && (facts
            .source_index
            .has_any(&[r#"PostForm("dest")"#, r#"FormValue("dest")"#]));
    if !caller_chosen_owner {
        return;
    }
    // Negative prefilters: service-owned spool path / fixed service identity.
    if facts
        .source_index
        .has_any(&["spoolDir", "serviceUID", "serviceGID"])
    {
        return;
    }

    // Primary signal: call facts — stdlib `os.Chown` callee.
    let Some(chown_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Chown")
    else {
        return;
    };

    let (line, col) = unit.line_col(chown_call.start_byte);
    emit::push_finding(
        &META_CWE_708,
        file,
        line,
        col,
        "the caller chooses both the ownership target and uid for a file operation",
        out,
    );
}
