use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_601(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_redirect = source.contains(r#""next""#)
        && (source.contains("c.Redirect(http.StatusFound, target)")
            || source.contains("http.Redirect(w, r, target, http.StatusFound)"));
    if !caller_redirect {
        return;
    }
    if source.contains("strings.HasPrefix(target, \"/\")")
        || source.contains("strings.Contains(target, \"//\")")
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

pub(crate) fn detect_cwe_918(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ssrf_fetch = source.contains("http.Get(target)")
        && (source.contains("c.Query(\"url\")") || source.contains("r.URL.Query().Get(\"url\")"));
    if !ssrf_fetch {
        return;
    }
    if source.contains("allowedHosts")
        || source.contains("allowedHostsPure")
        || source.contains("Hostname()")
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
