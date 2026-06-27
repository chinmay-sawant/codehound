use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_601(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_redirect = facts.source_index.has(r#""next""#)
        && (facts.source_index.has("c.Redirect(http.StatusFound, target)")
            || facts.source_index.has("http.Redirect(w, r, target, http.StatusFound)"));
    if !caller_redirect {
        return;
    }
    if facts.source_index.has("strings.HasPrefix(target, \"/\")")
        || facts.source_index.has("strings.Contains(target, \"//\")")
    {
        return;
    }

    let start_byte = source.find("target").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_601,
        file,
        line,
        col,
        "the redirect target comes from an unvalidated caller-controlled next parameter",
        out,
    );
}

pub(crate) fn detect_cwe_918(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ssrf_fetch = facts.source_index.has("http.Get(target)")
        && (facts.source_index.has("c.Query(\"url\")") || facts.source_index.has("r.URL.Query().Get(\"url\")"));
    if !ssrf_fetch {
        return;
    }
    if facts.source_index.has("allowedHosts")
        || facts.source_index.has("allowedHostsPure")
        || facts.source_index.has("Hostname()")
    {
        return;
    }

    let start_byte = source.find("http.Get(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_918,
        file,
        line,
        col,
        "an outbound request is sent to a caller-controlled URL without host allowlisting",
        out,
    );
}
