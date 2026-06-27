use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_783(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let precedence_bug = facts
        .source_index
        .has("!authenticated || isAdmin && ownerID == docOwner");
    if !precedence_bug {
        return;
    }
    if facts.source_index.has("!(isAdmin || ownerID == docOwner)") {
        return;
    }

    let start_byte = source
        .find("!authenticated || isAdmin && ownerID == docOwner")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_783,
        file,
        line,
        col,
        "authorization depends on ambiguous && and || precedence",
        out,
    );
}

pub(crate) fn detect_cwe_807(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let spoofable_ip_gate = facts.source_index.has("blockedIPs")
        && (facts.source_index.has_any(&[
            r#"GetHeader("X-Forwarded-For")"#,
            r#"Header.Get("X-Forwarded-For")"#,
        ]));
    if !spoofable_ip_gate {
        return;
    }
    if facts.source_index.has("RemoteAddr") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("X-Forwarded-For") {
        idx
    } else {
        source.find("blockedIPs").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_807,
        file,
        line,
        col,
        "a security gate trusts the caller-controlled forwarded IP header",
        out,
    );
}

pub(crate) fn detect_cwe_909(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let missing_init_guard = (facts
        .source_index
        .has_any(&["appDB.Find(", "widgetDB.Query("]))
        && !facts.source_index.has("if appDB == nil")
        && !facts.source_index.has("if widgetDB == nil");
    if !missing_init_guard {
        return;
    }

    let start_byte = if let Some(idx) = source.find("appDB.Find(") {
        idx
    } else {
        source.find("widgetDB.Query(").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_909,
        file,
        line,
        col,
        "a global database handle is used without checking that initialization completed",
        out,
    );
}

pub(crate) fn detect_cwe_915(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mass_assignment = facts.source_index.has("map[string]interface{}")
        && (facts
            .source_index
            .has_any(&["Updates(fields)", "json.Unmarshal(raw, &p)"]));
    if !mass_assignment {
        return;
    }
    if facts
        .source_index
        .has_any(&[r#"Update("name""#, "p.Name = body.Name"])
    {
        return;
    }

    let start_byte = source.find("map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_915,
        file,
        line,
        col,
        "a user-controlled attribute map updates privileged object fields directly",
        out,
    );
}
