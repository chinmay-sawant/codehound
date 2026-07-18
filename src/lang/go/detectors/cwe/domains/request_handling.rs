use super::super::common::argument_uses_identifier;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_601(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_redirect = facts.source_index.has(r#""next""#)
        && (facts
            .source_index
            .has("c.Redirect(http.StatusFound, target)")
            || facts
                .source_index
                .has("http.Redirect(w, r, target, http.StatusFound)"));
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

    // Cheap impossibility prefilter: no `http.Get` text ⇒ no SSRF fetch of this shape.
    if !facts.source_index.has("http.Get(") {
        return;
    }
    // Negative prefilters: host allowlisting / hostname validation evidence.
    if facts.source_index.has("allowedHosts")
        || facts.source_index.has("allowedHostsPure")
        || facts.source_index.has("Hostname()")
    {
        return;
    }

    // Primary signal: call facts — `http.Get` whose argument is a user-controlled
    // binding assigned from a `url` query parameter (not an arbitrary query key).
    let Some(get_call) = facts.call_facts.iter().find(|call| {
        if call.callee.as_ref() != "http.Get" {
            return false;
        }
        call.arguments.iter().any(|arg| {
            facts.input_bindings.iter().any(|binding| {
                binding.kind == InputKind::UserControlled
                    && argument_uses_identifier(arg, &binding.name)
                    && facts.assignments.iter().any(|assignment| {
                        assignment.name.as_ref() == binding.name.as_ref()
                            && (assignment.expr.contains(r#"Query("url")"#)
                                || assignment.expr.contains(r#"Get("url")"#))
                    })
            })
        })
    }) else {
        return;
    };

    let (line, col) = unit.line_col(get_call.start_byte);
    emit::push_finding(
        &META_CWE_918,
        file,
        line,
        col,
        "an outbound request is sent to a caller-controlled URL without host allowlisting",
        out,
    );
}
